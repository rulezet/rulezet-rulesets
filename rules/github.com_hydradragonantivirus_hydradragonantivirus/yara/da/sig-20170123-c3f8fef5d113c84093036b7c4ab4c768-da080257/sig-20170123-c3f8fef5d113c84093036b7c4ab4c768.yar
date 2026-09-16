rule sig_20170123_c3f8fef5d113c84093036b7c4ab4c768 {
  meta:
    description = "datamaliciousorder - file 20170123_c3f8fef5d113c84093036b7c4ab4c768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22f5058d79dc55a20ffc785d7364183d1a008011fabe0ec2fcfbc8c218fe90e3"

  strings:
    $s1 = "//if ([\"usu\", \"uxwazgev\", \"ruxko\", \"eqy\", \"osjifme\", \"nicn\", \"keksa\", \"arokxe\", \"ugi\", \"lverserq\", \"buslik" ascii
    $s2 = "//if ([\"usu\", \"uxwazgev\", \"ruxko\", \"eqy\", \"osjifme\", \"nicn\", \"keksa\", \"arokxe\", \"ugi\", \"lverserq\", \"buslik" ascii
    $s3 = "zzoxjapb1 = this[[\"ycqofb\", \"kawu\", \"aljo\", \"rmimep\", \"cuxcecco\", \"onyfw\", \"tadfi\", \"fris\", \"urdudi\", \"gfizle" ascii
    $s4 = "zzoxjapb1 = this[[\"ycqofb\", \"kawu\", \"aljo\", \"rmimep\", \"cuxcecco\", \"onyfw\", \"tadfi\", \"fris\", \"urdudi\", \"gfizle" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}