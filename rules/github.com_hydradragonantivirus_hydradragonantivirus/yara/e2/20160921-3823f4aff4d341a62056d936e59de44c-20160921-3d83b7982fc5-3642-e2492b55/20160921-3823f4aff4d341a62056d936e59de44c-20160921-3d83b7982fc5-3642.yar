rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_3d83b7982fc5_3642 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash3       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash4       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";}" ascii
    $s3 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return" ascii
    $s4 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Q" ascii
    $s5 = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(" ascii
    $s6 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}