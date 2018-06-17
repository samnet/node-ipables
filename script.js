const Tesserarius = require("tesserarius");
const cmd = require('node-cmd');
const Bluebird = require('bluebird');

const ipt = new Tesserarius();
const getAsync = Bluebird.promisify(cmd.get, { multiArgs: true, context: cmd })

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
function readBytesCounter(table, ip) {
  let bash_command = "iptables -L " + table;
  bash_command += "  -n -v -x | grep " + ip + "0.0.0.0 | awk  '{print $2}'"
  getAsync(bash_command);
}

// obtain adress of peers in local network
function getIpAdressOfPeer(){
  const arpCmd = "arp-scan --interface=ap0 --localnet | grep 192 | awk  '{print $1}'";
  return getAsync(arpCmd);
}

// 1. drop everything apart from etherscan
ipt.set_policy("FORWARD", "DROP", (err) => showErr(err));
ipt.flush("FORWARD", (err) => showErr(err));
allowAdress("104.25.244.14");

// 2. create an exception for IP address X
getIpAdressOfPeer()
  .then(data => {
    console.log('ipPeer', data);
    return data;
  })
  .then(ipPeer => {
    return readBytesCounter(ipPeer)
  })
 

// 3. if traffic from IP adress X exceed Y, delete the exception



