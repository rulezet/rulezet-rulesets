rule sig_20161128_47f98f11ca575b2309f4370f5eff38c7 {
  meta:
    description = "datamaliciousorder - file 20161128_47f98f11ca575b2309f4370f5eff38c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73fdc73d5a2d3ae99a686e9a3d761f92df20255ff7faf66201fbca9afa3ca38d"

  strings:
    $s1  = "return new Function(bhuzcywq + opjimdafj + \"object')[ovegi]('C:\\\\\\\\')['type']['length'] > 1\");" fullword ascii
    $s2  = "var opjimdafj = \"Object('scripting.fileSystem\";" fullword ascii
    $s3  = "if (iziziqe === undefined) {" fullword ascii
    $s4  = "var ifzycx = false;" fullword ascii
    $s5  = "var opzijxeh = null;" fullword ascii
    $s6  = "return ukoczih;" fullword ascii
    $s7  = "return wajmupqo;" fullword ascii
    $s8  = "return ypecc;" fullword ascii
    $s9  = "function jpijnacq() {" fullword ascii
    $s10 = "function azqerzyqa() {" fullword ascii
    $s11 = "function ykwotw() {" fullword ascii
    $s12 = "function ibaq() {" fullword ascii
    $s13 = "switch (ykwotw()()) {" fullword ascii
    $s14 = "var sbebalzozg = false;" fullword ascii
    $s15 = "return uzbuna;" fullword ascii
    $s16 = "var bhuzcywq = \"return new ActiveX\";" fullword ascii
    $s17 = "function wanse() {" fullword ascii
    $s18 = "var xoti = null;" fullword ascii
    $s19 = "var ebmasoqh = false;" fullword ascii
    $s20 = "if (wanse() == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}