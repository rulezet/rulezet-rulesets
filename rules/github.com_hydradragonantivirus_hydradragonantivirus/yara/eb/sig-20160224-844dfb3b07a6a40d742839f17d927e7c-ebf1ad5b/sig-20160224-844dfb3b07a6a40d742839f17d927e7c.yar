rule sig_20160224_844dfb3b07a6a40d742839f17d927e7c {
  meta:
    description = "datamaliciousorder - file 20160224_844dfb3b07a6a40d742839f17d927e7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "866ba2a042e17cf244b96a8f3bdb3b03edb7a174ffdce29175804c6bdb7cd0e1"

  strings:
    $s1 = "function btoa(conservatorytIL, manneredEOw, unanimityvxk, vassalect, boastzaz, enervateMhR, doggedc2Y, tawdrym8I, passageOgI) {" fullword ascii
    $s2 = "        return WScript[dissemblet9m](lineamentNG2);" fullword ascii
    $s3 = "    var polemicalgNb = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s4 = "var mordanttGW = function() {" fullword ascii
    $s5 = "    var loutd68 = String(passageOgI);" fullword ascii
    $s6 = "var erstwhileznv = function(caballwP) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}