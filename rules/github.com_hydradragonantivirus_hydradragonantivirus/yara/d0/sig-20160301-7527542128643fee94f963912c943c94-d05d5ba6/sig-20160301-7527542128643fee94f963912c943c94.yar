rule sig_20160301_7527542128643fee94f963912c943c94 {
  meta:
    description = "datamaliciousorder - file 20160301_7527542128643fee94f963912c943c94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c1c3c26ee569b51ce016b8292b000567422d6d19b7dfa70746f2e38e3a0c1cb"

  strings:
    $s1 = "agentReserve = (\"t\\u0072\" + \"a\\u006es\\u006c\\u0061\" + \"\\u0074\\u006fr\", \"\\u0070eak\", function String.prototype.tran" ascii
    $s2 = "agentReserve = (\"t\\u0072\" + \"a\\u006es\\u006c\\u0061\" + \"\\u0074\\u006fr\", \"\\u0070eak\", function String.prototype.tran" ascii
    $s3 = "while (trajectoryAutomobile[(\"\\u0061n\\u0074\" + \"enna\", \"\\u0073\\u0079nt\" + \"\\u0068\" + \"es\\u0069\\u0073\", \"\\u007" ascii
    $s4 = "while (trajectoryAutomobile[(\"\\u0061n\\u0074\" + \"enna\", \"\\u0073\\u0079nt\" + \"\\u0068\" + \"es\\u0069\\u0073\", \"\\u007" ascii
    $s5 = "genesisAcademy = (((0 + 0) ^ (1 & 1)), this);" fullword ascii
    $s6 = "} catch (galleryLeader) {};" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    all of them
}