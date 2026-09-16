rule sig_20151130_522c53a1cc378236f9abc058cbf872c2 {
  meta:
    description = "datamaliciousorder - file 20151130_522c53a1cc378236f9abc058cbf872c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c0a7bdc22abe8acf00ef0a3b55edac412f2e8ff24c74ee2a3d06176c2187e48"

  strings:
    $s1  = "var gbZBKxrTkZkYH = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "zzauIjtSBHO.onreadystatechange = function ()" fullword ascii
    $s3  = "with(NbjdnsclFfiBPsM(\"ADOD\" + dXuHLF))" fullword ascii
    $s4  = "zzauIjtSBHO.open(/*s255071nM129496eOZ*/\"G\" + (3772563, /*s651210nM354853eOZ*/ 4619129, /*dca514083zYtzkrxTK515756IlaIWQJrHGjLq" ascii
    $s5  = "type = 1;" fullword ascii
    $s6  = "open();" fullword ascii
    $s7  = "trtopmsP = false; " fullword ascii
    $s8  = "if (((new Date())>0,8555))" fullword ascii
    $s9  = "function NbjdnsclFfiBPsM(lwTVyazSvO) " fullword ascii
    $s10 = "})(this)/*65295694777121884392958373926*/" fullword ascii
    $s11 = "write(zzauIjtSBHO.ResponseBody);" fullword ascii
    $s12 = "while (trtopmsP) {uDNUZbn}" fullword ascii
    $s13 = "var trtopmsP = true, dXuHLF = (\"B.St\"+(232489, \"ream\"));" fullword ascii
    $s14 = "return qCLHkkJ;" fullword ascii
    $s15 = "return new RXmqtHRzHdejPI.ActiveXObject(lwTVyazSvO)" fullword ascii
    $s16 = "(function (RXmqtHRzHdejPI) {" fullword ascii
    $s17 = "igMcqGRHjo = function (MNxmxraR, qCLHkkJ, TmmskWJLelQiG) {" fullword ascii
    $s18 = "jNQmXamgjYPW*/ \"ET\" /*dcazYtzkrx76588TKIlaIWQJr123008HGjLqXIjNQmX726007amgjYPW*/), MNxmxraR, false);" fullword ascii

  condition:
    uint16(0) == 0x6628 and
    8 of them
}