rule sig_20160301_543779a26e2ecbe576f199beb6fd6b62 {
  meta:
    description = "datamaliciousorder - file 20160301_543779a26e2ecbe576f199beb6fd6b62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef869e85d0f139f6114c10f421e9d1bf8aaad9c6ad2ec4e190cfbe2e38b9e837"

  strings:
    $s1 = "transcriptionRecord = (((326 - 157), (Math.pow(170, 2) - 28735), 101 * 2), this);" fullword ascii
    $s2 = "while (mileAuthority[(\"\\u0073p\\u0068e\\u0072i\\u0063a\\u006c\", function String.prototype.privateExport() {" fullword ascii
    $s3 = "} catch (preambleMotor) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}