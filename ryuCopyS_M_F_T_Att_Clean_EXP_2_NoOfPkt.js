// correct one | everything works fine

var ryu = '127.0.0.1';
var controls = {};
// var threshold = 100000/8;

// 1000000/8 = 1MBits/sec
// M = 000,000
// K = 000

setFlow('udp_reflection', {
    // keys: 'ipdestination,udpsourceport',
    keys: 'ipsource,ipdestination,udpsourceport',
    // value: 'bytes',
    value: 'frames',
    log:true
});

setThreshold('udp_reflection_attack', {
    metric: 'udp_reflection',
    // value: threshold,
    value: 200,
    byFlow: true,
    timeout: 2
});

var attackStatus = 0;
var attackerIPs = [];
// var udpPort;

setEventHandler(function (evt) {
    // don't consider inter-switch links
    var link = topologyInterfaceToLink(evt.agent, evt.dataSource);
    if (link) return;

    // get port information
    var port = topologyInterfaceToPort(evt.agent, evt.dataSource);
    if (!port) return;

    // need OpenFlow info to create Ryu filtering rule
    if (!port.dpid || !port.ofport) return;

    // we already have a control for this flow
    if (controls[evt.flowKey]) {
        return;
    };

    var [ipsource, ipdestination, udpsourceport] = evt.flowKey.split(',');        //<--
    // var [ipdestination, udpsourceport] = evt.flowKey.split(',');         //<--
    // udpPort = udpsourceport;
    var msg = {                     //msg to be sent to Ryu
        priority: 40000,
        dpid: parseInt(port.dpid, 16),
        match: {
            in_port: port.ofport,               // port (spoofed?)
            dl_type: 0x800,
            nw_dst: ipdestination + '/32',      // dstIP 
            nw_src: ipsource + '/32',           // srcIP
            nw_proto: 17,
            tp_src: udpsourceport
        }
    };

    var resp = http2({
        url: 'http://' + ryu + ':8080/stats/flowentry/add',     //add
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        operation: 'post',
        body: JSON.stringify(msg)
    });

    controls[evt.flowKey] = {
        time: Date.now(),
        threshold: evt.thresholdID,                         // * threshold triggered 1st
        agent: evt.agent,
        metric: evt.dataSource + '.' + evt.metric,
        msg: msg
    };

    logInfo("blocking " + evt.flowKey + " (large flow detected)");
    
    attackStatus = 1;
    // attackerIPs.unshift(evt.flowKey);
    attackerIPs.unshift(JSON.stringify(evt.flowKey));
    logInfo(attackerIPs);

}, ['udp_reflection_attack']);

// if sourceIP = an attacker, dont calculate the entropy

var B = 1;
var std = 1;
var D= 1;
var H = 1;
var mean = 1;

var entArray = [1,1,1,1]; //use unshift.entArray(n) 

setIntervalHandler(function () {
    var top = activeFlows('ALL','udp_reflection',20,0.1);    //monitor every udp packets?
    // logInfo(JSON.stringify(top,null,1));

    var ent = [];
    var valueTotal = 0;
    
    var entAtt = [];
    var valueTotalAtt = 0;

    // get total value first.
    if (Object.keys(top).length === 0) {
    } else {
        var noOfPackets = JSON.parse(JSON.stringify(top));
        for (var i = 0; i < noOfPackets.length; i++) {
            if (attackerIPs.includes( JSON.stringify(noOfPackets[i]["key"]) )) {
                // valueTotal = 0;
                var value = Math.ceil(noOfPackets[i]["value"]);
                valueTotalAtt += value;
                continue;                
            }
            var value = Math.ceil(noOfPackets[i]["value"]);
            valueTotal += value;

            valueTotalAtt += value;
            // logInfo("valueTotal: " + valueTotal) // appear 3 times?
        }
    }

    if (Object.keys(top).length === 0) {        //only see udp 
    } else {
        // logInfo("no of connections: " + Object.keys(top).length)   //=n
        var noOfPackets = JSON.parse(JSON.stringify(top));
        // monitor all srcIPs & dstIPs, below already correct

        for (var i = 0; i < noOfPackets.length; i++) {
            // logInfo(JSON.stringify(noOfPackets[i]["key"]));
            if (attackerIPs.includes( JSON.stringify(noOfPackets[i]["key"]) )) {
                // logInfo("success");
                var value = Math.ceil(noOfPackets[i]["value"]);
                entAtt[i] = (value/valueTotalAtt)*Math.log2( 1/(value/valueTotalAtt) );
                
                ent[i] = -1;
                // ent not being calculated
                
                continue;
            } // else?
            
            var value = Math.ceil(noOfPackets[i]["value"]);
            ent[i] = (value/valueTotal)*Math.log2( 1/(value/valueTotal) );

            entAtt[i] = (value/valueTotalAtt)*Math.log2( 1/(value/valueTotalAtt) );
        }

        // calc entropy here
        let sum = 0;
        for (let i = 0; i < ent.length; i++) {
            // logInfo("ent[]:" + ent[i]);
            if (ent[i] == -1) {
                continue;
            }
            sum += ent[i];
        }
        // logInfo("entropy:" + sum + " B:" + B);

        // calc entropy after attack 
        let sumAtt = 0;
        for (let i = 0; i < entAtt.length; i++) {
            // logInfo("ent[]:" + entAtt[i]);
            sumAtt += entAtt[i];
        }
        // logInfo("entropyAtt:" + sumAtt);

        // mitigation calculation
        if (attackStatus==0) {      // this should depend on connections that are not attacked.
            // var H = sum;
            H = sum;
            entArray.unshift(H); 
            var N = 4; //last 4 entropy
            mean = (entArray[1]+entArray[2]+entArray[3]+entArray[4])/N;
            
            var stdSum = 0;
            for (let i=1; i<5; i++) {   
                stdSum += Math.pow( ((entArray[i])-mean),2 );
                // logInfo("stdSum" + stdSum);                 //debug log
            }
            std = Math.sqrt((1/N)*(stdSum));;

            if (H < 0.5*mean) {
                B = B - 1;
                if (B < 1) {
                    B = 1;
                }
            } 
            if ((0.5*mean) <= H < (1.5*mean)) {
                B = B;
            } 
            if (H > 1.5*mean) {
                B = B + 1;
            }
        }

        let DAtt = Math.abs(mean - sumAtt);
        // if (DAtt > B*std) {
        //     logInfo("DAtt attack detected,B:" + B);
        // }


        D = Math.abs(mean - sum);

        // logInfo("D > B*std \t"+ D + ">" + B*std);     //debug log
        
        // threshold = ???;
        // if (D > B*std) {
        //     logInfo("attack detected,B:" + B);
        // }

        // logInfo everything
        if (DAtt > B*std) {
            logInfo("ent:" + sum + " entA:" + sumAtt + " D_Att:" + DAtt + " B:"+ B + " LARGE FLOW ");
        } else {
            logInfo("ent:" + sum + " entA:" + sumAtt + " D_Att:" + DAtt + " B:"+ B );
        }
        
        // logInfo("");
    }

    var now = Date.now();
    for (var key in controls) {
        let rec = controls[key];
        
        attackStatus = 0; // 

        // keep control for at least 10 seconds
        // if (now - rec.time < 10000) continue;
        if (now - rec.time < 3000) continue;
        // keep control if threshold still triggered
        if (thresholdTriggered(rec.threshold, rec.agent, rec.metric, key)) continue;        //threhold triggered 2nd time?;

        var resp = http2({
            url: 'http://' + ryu + ':8080/stats/flowentry/delete',      //detete
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            operation: 'post',
            body: JSON.stringify(rec.msg)
        });

        delete controls[key];

        logInfo("unblocking " + key);
        // attackStatus = 0;
        
        attackerIPs = attackerIPs.filter(i=>(i!=JSON.stringify(key)));
        // logInfo(attackerIPs);
        // logInfo("JSON.stringify(key)" + JSON.stringify(key));
    }
}, 5);

setFlowHandler(function(rec) {
    logInfo(JSON.stringify(rec,null,1));
}, ['pair']);
