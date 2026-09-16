rule erastealer {
  meta:
    description = "datamaliciousorder - file erastealer.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "184009bc20c5ab88e045791b83fcc93fdbe1a90061cde9832f4076b934d411f4"

  strings:
    $x1  = "  const file = `C:\\\\Users\\\\${process.env.USERNAME}\\\\AppData\\\\Roaming\\\\Exodus\\\\exodus.wallet`;" fullword ascii
    $s2  = "  exec(`start /B cmd /c ${cmd}`, (error, stdout, stderr) => {" fullword ascii
    $s3  = "          )}\\\\Update.exe\" --processStart ${executable}`," fullword ascii
    $s4  = "      name: `${process.env.USERNAME} - Infos PC`," fullword ascii
    $s5  = "          execSync(`taskkill /IM ${process} /F`);" fullword ascii
    $s6  = "    roaming: process.env.APPDATA," fullword ascii
    $s7  = "  const url = `http://ip-api.com/json/${ip}?fields=continent,country,regionName,city,proxy,hosting`;" fullword ascii
    $s8  = "  var ip = await axios.get(\"https://www.myexternalip.com/raw\");" fullword ascii
    $s9  = "  LOCAL = process.env.LOCALAPPDATA," fullword ascii
    $s10 = "const local = process.env.LOCALAPPDATA;" fullword ascii
    $s11 = "const { execSync, exec } = require(\"child_process\");" fullword ascii
    $s12 = "    temp: process.env.TEMP," fullword ascii
    $s13 = "      console.error(`Error executing command: ${error.message}`);" fullword ascii
    $s14 = "      const link_download2 = await getPasswords();" fullword ascii
    $s15 = "  await httpx(`${injection_url}`)" fullword ascii
    $s16 = "async function getPasswords() {" fullword ascii
    $s17 = "    local: process.env.LOCALAPPDATA," fullword ascii
    $s18 = "      { name: \"Utilisateur\", value: `\\`${process.env.USERNAME}\\``, inline: true }," fullword ascii
    $s19 = "      name: `${process.env.USERNAME} | IP Informations`," fullword ascii
    $s20 = "          name: `${process.env.USERNAME} | Browsers Data`," fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}