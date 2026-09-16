rule sig_20170425_227d9a091d8156e5ebccab7f76e3f79e {
  meta:
    description = "datamaliciousorder - file 20170425_227d9a091d8156e5ebccab7f76e3f79e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21c5b7b824612fc2c8d0b7f1c0a12d1d9fb8f1f0cd6a7a8a2d689488f6d6601f"

  strings:
    $s1 = "if (RGZIsquUkFCAXhpV.FolderExists(\"c:\\\\W\"+\"IND\"+\"oWs\") == true) {" fullword ascii
    $s2 = "return cxwVtbmeQDAoardsh.split(flbOsWMdojkZLwStRGq).join(zdVjtbBCZROeLxDlIMy); }" fullword ascii
    $s3 = "function upqndsiyDQPNrImfO(cxwVtbmeQDAoardsh, flbOsWMdojkZLwStRGq, zdVjtbBCZROeLxDlIMy) { " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}