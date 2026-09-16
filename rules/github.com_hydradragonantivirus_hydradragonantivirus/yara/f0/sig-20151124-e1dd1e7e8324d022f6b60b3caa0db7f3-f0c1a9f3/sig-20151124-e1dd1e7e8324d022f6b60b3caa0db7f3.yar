rule sig_20151124_e1dd1e7e8324d022f6b60b3caa0db7f3 {
  meta:
    description = "datamaliciousorder - file 20151124_e1dd1e7e8324d022f6b60b3caa0db7f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6402b8f32b6955f75317c19c35499c2a1817a9c7aeb51e5a0b83cf0e07bbf899"

  strings:
    $s1  = "var cTwoWDSh = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "xTqKEAmAM.onreadystatechange = function ()" fullword ascii
    $s3  = "with(ULkwjGJGnWG(\"ADOD\" + jkFZqNhrYZWkwl))" fullword ascii
    $s4  = "xTqKEAmAM.open(\"G\" + (3192220, 4175797, /*dca156329zYtzkrxTK455578IlaIWQJrHGjLqXIjNQmXamgjYPW*/ \"ET\" /*dcazYtzkrx175829TKIla" ascii
    $s5  = "type = 1;" fullword ascii
    $s6  = "var WuLhqkJdtaacjb = true, jkFZqNhrYZWkwl = (\"B.St\"+(993982, \"ream\"));" fullword ascii
    $s7  = "WuLhqkJdtaacjb = false; " fullword ascii
    $s8  = "if (((new Date())>0,1552))" fullword ascii
    $s9  = "r353666HGjLqXIjNQmX585881amgjYPW*/), HdjxVffbRet, false);" fullword ascii
    $s10 = "(function (acMRvoX) {" fullword ascii
    $s11 = "open();" fullword ascii
    $s12 = "return new acMRvoX.ActiveXObject(ubLrFIZDoYnE)" fullword ascii
    $s13 = "function ULkwjGJGnWG(ubLrFIZDoYnE) " fullword ascii
    $s14 = "write(xTqKEAmAM.ResponseBody);" fullword ascii
    $s15 = "PnPtHKXuORqDqyM = function (HdjxVffbRet, KuRguBRxAJGxrhe, JLKatIaUwWO) {" fullword ascii
    $s16 = "return KuRguBRxAJGxrhe;" fullword ascii
    $s17 = "})(this)/*233104712588347787739234524290*/" fullword ascii
    $s18 = "while (WuLhqkJdtaacjb) {SnThLj}" fullword ascii

  condition:
    uint16(0) == 0x6628 and
    8 of them
}