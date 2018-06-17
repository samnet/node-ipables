const Tesserarius = require("tesserarius");
const ipt = new Tesserarius();
const cmd = require('node-cmd');

function showErr(err) {console.log(err);}


function allowAdress(anIP) { // create a new rule to allow specific traffic
  const ruleSrc = {
    policy: "ACCEPT",
    source: anIP
  };
  const ruleDst = {
    policy: "ACCEPT",
    destination: anIP
  };
  ipt.add_rule("FORWARD", ruleSrc, (err) => showErr(err));
  ipt.add_rule("FORWARD", ruleDst, (err) => showErr(err));
}

function dropAdress(anIP) { // delete existing rule.. does not create new ones
  const ruleSrc = {
    policy: "ACCEPT",
    source: anIP
  };
  const ruleDst = {
    policy: "ACCEPT",
    destination: anIP
  };
  ipt.delete_rule("FORWARD", ruleSrc, (err) => showErr(err));
  ipt.delete_rule("FORWARD", ruleDst, (err) => showErr(err));
}

// reading current counter for given address
function readBytesCounter(table, ip){
  bash_command = "iptables -L " + table;
  bash_command += "  -n -v -x | grep " + ip + "0.0.0.0 | awk  '{print $2}'"
  cmd.get(
    bash_command,
    function(err, data, stderr){
      return(data);
    }
  );
}

// obtain adress of peers in local network
function getIpAdressOfPeer(cb){
cmd.get(
        "arp-scan --interface=ap0 --localnet | grep 192 | awk  '{print $1}'",
		cb
    );
}

// 1. drop everything apart from etherscan
ipt.set_policy("FORWARD", "DROP", (err) => showErr(err));
ipt.flush("FORWARD", (err) => showErr(err));
allowAdress("104.25.244.14");

// 2. create an exception for IP address X
let ipPeer;
getIpAdressOfPeer(        function(err, data, stderr){
            ipPeer = data;
            console.log('the current working dir is : ',ipPeer)
        })
        
            //var cmd=require('node-cmd');


    

//setTimeout(function(){
//  console.log("Hello");
//  allowAdress(ipPeer)
//}, 30000);

// 3. if traffic from IP adress X exceed Y, delete the exception



