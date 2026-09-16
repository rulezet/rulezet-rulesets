rule sig_20160301_0cae8db3a8e1f60fd4e8d3f8113895a3 {
  meta:
    description = "datamaliciousorder - file 20160301_0cae8db3a8e1f60fd4e8d3f8113895a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc56d01c14d862b9fbc0352e6b9e5d07cc8425fa2e08d5e10ac3a621bf5bbd3a"

  strings:
    $x1 = "verticalCertificate = conventionCommander[(\"accuracy\", \"ExpandEnvironmentStrings\")]((\"occasion\", \"zombie\", \"autonomous" ascii
    $s2 = "verticalCertificate = conventionCommander[(\"accuracy\", \"ExpandEnvironmentStrings\")]((\"occasion\", \"zombie\", \"autonomous" ascii
    $s3 = "consultantAlternative = (((Math.pow(102, 2) - 10244) + (75 & 127)), this);" fullword ascii
    $s4 = "while (syndicatePrinter[(\"readystate\")] < (2) * 2) {" fullword ascii
    $s5 = "} catch (pedalConsultant) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and all of them
}