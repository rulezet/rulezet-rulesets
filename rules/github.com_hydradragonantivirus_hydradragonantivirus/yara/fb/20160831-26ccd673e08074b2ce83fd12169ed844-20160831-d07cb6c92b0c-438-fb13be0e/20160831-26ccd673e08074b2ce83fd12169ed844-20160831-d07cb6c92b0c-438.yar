rule _20160831_26ccd673e08074b2ce83fd12169ed844_20160831_d07cb6c92b0c_438 {
  meta:
    description = "datamaliciousorder - from files 20160831_26ccd673e08074b2ce83fd12169ed844.js, 20160831_d07cb6c92b0c1547f2d76ca3d157384b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "674a05921da575cf2fb8f992fa17d7228534327784d62414d585d46b1944fcc6"
    hash2       = "c89985ce554ed1332d8559d49cb2761e4624a09888aff585187aea6d005fdc42"

  strings:
    $s1 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s2 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!Qsshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuckin" ascii
    $s5 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuck" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}