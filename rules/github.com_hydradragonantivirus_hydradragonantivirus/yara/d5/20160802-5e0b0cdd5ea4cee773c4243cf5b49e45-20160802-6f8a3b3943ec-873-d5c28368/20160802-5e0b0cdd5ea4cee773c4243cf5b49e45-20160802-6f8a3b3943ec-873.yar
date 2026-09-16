rule _20160802_5e0b0cdd5ea4cee773c4243cf5b49e45_20160802_6f8a3b3943ec_873 {
  meta:
    description = "datamaliciousorder - from files 20160802_5e0b0cdd5ea4cee773c4243cf5b49e45.js, 20160802_6f8a3b3943ecf61763c5cd034903a47d.js, 20160802_bbe19f018fdffe668a3aae64b421f965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "807ae2229b7975c1690bdd260f508be595bcced39adc62f78c42699d7b8c6044"
    hash2       = "5c33ba1bf78e59749625f33f9e1c7655dbc435674e25ca3599b97972646230e4"
    hash3       = "25bbec6f1a437208625ba7b78d87fae5bafdfb17a9ecc55a647cc7d589f3ea48"

  strings:
    $s1 = ";\\x0d\\n\\x76ar Uh6 = \"len\"\\x20+ \"\\x22\\x3b\\r\\nfunct\\x69o\\x6e\\x20KEx3(TEw){return TEw;};va\\x72 GAa9 =\\x20\"GET\"\\x" ascii
    $s2 = "\" \\x2b \"\";\\r\\nvar \\x4aW\\x7a3 =\\x20\"n\" + \\x22\";\\x0d\\n\\x76ar APp7 = \"ope\" + \"\";\\r\\n\\x66unction Xp6(Ik){retu" ascii
    $s3 = "unct\\x69on STv\\x30(Ra0){return Ra0;};var \\x54Vr\\x33 \\x3d \"e\" + \"\";\\r\\nvar\\x20VTk0 = \\x22wri\\x74\" + \"\\x22;\\r\\n" ascii
    $s4 = "2ream\" + \"\";\\r\\n\\x76ar Yv\\x20= \"St\" + \\x22\";\\r\\nvar\\x20XOs = \"DB.\\x22 + \"\";\\x0d\\nf\\x75nction \\x56w3(NAa){r" ascii
    $s5 = " \"\";\\r\\nfunction DEk\\x30(Ja\\x29{return Ja;};functio\\x6e \\x50J\\x68(M\\x54j4){r\\x65turn\\x20MTj4;};var\\x20RVy = \"e\" +" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}