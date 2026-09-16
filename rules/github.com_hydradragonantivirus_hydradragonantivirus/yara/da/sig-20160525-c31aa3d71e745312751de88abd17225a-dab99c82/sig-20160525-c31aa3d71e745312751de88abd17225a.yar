rule sig_20160525_c31aa3d71e745312751de88abd17225a {
  meta:
    description = "datamaliciousorder - file 20160525_c31aa3d71e745312751de88abd17225a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1332241a4603c2ff3dc5c726d38af11e294181130b1619b0106c41901fb835a"

  strings:
    $s1 = "n\" = sdnetm rav;};imm nruter{)imm(rerednerm noitcnuf\\n;\"Te67x\\\\16x\\\\35x\\\\\" = eixodn rav\\n;\"iFf6x\\\\\" = gsmn rav\\n" ascii
    $s2 = " = ssorcaq rav\\n;\"07x\\\\s\" = rerednerq rav\\n;\"ic6x\\\\\" = imq rav\\n;\"e36x\\\\\" = eixodr rav\\n;\"t76x\\\\nel\" = gsmr " ascii
    $s3 = "PITQ\" = ecapsetihwxelfh rav;};imh nruter{)imh(rerednerh noitcnuf\\n;\"nec6x\\\\\" = eixodi rav\\n;\"t76x\\\\\" = gsmi rav\\n;\"" ascii
    $s4 = "f;};reredneri nruter{)reredneri(cthi noitcnuf;};tsilslianbmuhtoi nruter{)tsilslianbmuhtoi(ssorcai noitcnuf;};deerdi nruter{)deer" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}