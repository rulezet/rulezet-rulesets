rule sig_20160526_57c1a60fb044c4e4e377df730268acc5 {
  meta:
    description = "datamaliciousorder - file 20160526_57c1a60fb044c4e4e377df730268acc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2430a3496d293f494c29f16829936b033db2ebd9a2e0094dc4cdb92484290867"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]cT" ascii
    $s2 = "n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}