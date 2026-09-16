rule sig_23922baef56454f8a00a5832857705fa646d1c8441df1dff75a175add3df {
  meta:
    description = "datamaliciousorder - file 23922baef56454f8a00a5832857705fa646d1c8441df1dff75a175add3dffc69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23922baef56454f8a00a5832857705fa646d1c8441df1dff75a175add3dffc69"

  strings:
    $s1  = "// Configuration - replace with your actual bot token" fullword ascii
    $s2  = "    console.log(colors[color] + message + colors.reset);" fullword ascii
    $s3  = "process.on('uncaughtException', (error) => {" fullword ascii
    $s4  = "// JavaScript Version (Node.js)" fullword ascii
    $s5  = "        process.stdin.on('data', process.exit.bind(process, 0));" fullword ascii
    $s6  = "// Error handling for the entire script" fullword ascii
    $s7  = "    process.stdin.on('data', process.exit.bind(process, 0));" fullword ascii
    $s8  = "function getPublicIP() {" fullword ascii
    $s9  = "// Device Collector Script for Discord Bot" fullword ascii
    $s10 = "    log(\"    Discord Device Collector\", 'magenta');" fullword ascii
    $s11 = " Device Information:\", 'green');" fullword ascii
    $s12 = "    process.stdin.setRawMode(true);" fullword ascii
    $s13 = "        process.stdin.setRawMode(true);" fullword ascii
    $s14 = "// Start the script" fullword ascii
    $s15 = "async function getDeviceInfo() {" fullword ascii
    $s16 = "function log(message, color = 'white') {" fullword ascii
    $s17 = "function getLocalIP() {" fullword ascii
    $s18 = " Registration failed!\", 'red');" fullword ascii
    $s19 = " Failed to collect device information!\", 'red');" fullword ascii
    $s20 = " Error registering with Discord: ${error.message}`, 'red');" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    8 of them
}