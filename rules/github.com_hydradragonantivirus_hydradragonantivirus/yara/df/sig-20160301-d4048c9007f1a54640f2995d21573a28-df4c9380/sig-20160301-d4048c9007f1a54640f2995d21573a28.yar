rule sig_20160301_d4048c9007f1a54640f2995d21573a28 {
  meta:
    description = "datamaliciousorder - file 20160301_d4048c9007f1a54640f2995d21573a28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de6fa0eb0dfbbbc78db944de91580c99964a92c3973fee74bda9238bf0372d90"

  strings:
    $x1 = "operativeHobby = imageEconomy[(\"student\", \"ExpandEnvironmentStrings\")]((\"arena\", \"actor\", \"%TEMP%/\")) + (\"violet\", " ascii
    $s2 = "operativeHobby = imageEconomy[(\"student\", \"ExpandEnvironmentStrings\")]((\"arena\", \"actor\", \"%TEMP%/\")) + (\"violet\", " ascii
    $s3 = "automobileStudio = structureUniform[(\"period\", \"WScript\")][(\"memorial\", \"pseudonym\", \"inert\", \"finish\", \"CreateObje" ascii
    $s4 = "automobileStudio[(\"natural\", \"open\")]((\"phrase\", \"GET\"), (\"archive\", \"anatomy\", \"obligation\", function String.prot" ascii
    $s5 = "automobileStudio[(\"natural\", \"open\")]((\"phrase\", \"GET\"), (\"archive\", \"anatomy\", \"obligation\", function String.prot" ascii
    $s6 = "structureUniform = (((68 ^ 10) * (36 / 18) + (58 / 29)), this);" fullword ascii
    $s7 = "while(automobileStudio[(\"ballast\", \"central\", \"readystate\")] < ((3456 / 48) / (19 & 30))) {" fullword ascii
    $s8 = "Paragraph() {" fullword ascii
    $s9 = "} catch(amplitudeObligation) {};" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and all of them
}