rule sig_20160224_d98a195006074778c7688681d0f5ad56 {
  meta:
    description = "datamaliciousorder - file 20160224_d98a195006074778c7688681d0f5ad56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e1765777655d9b8cf0e31e57b79341b3d2639179dc3856e1c5c01deb9909b5c"

  strings:
    $s1 = "    var brooki1O = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "function btoa(commiserateuSb, exigencyedx, sleightziT, brawnu84, specioustlL, omniscientkvw, apologistCaw, genesisavT, furnishqT" ascii
    $s3 = "function btoa(commiserateuSb, exigencyedx, sleightziT, brawnu84, specioustlL, omniscientkvw, apologistCaw, genesisavT, furnishqT" ascii
    $s4 = "        return WScript[besiegesdh](dintPXo);" fullword ascii
    $s5 = "var oratorioeuS = function(theoryQWA) {" fullword ascii
    $s6 = "var retentivePIt = function() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}