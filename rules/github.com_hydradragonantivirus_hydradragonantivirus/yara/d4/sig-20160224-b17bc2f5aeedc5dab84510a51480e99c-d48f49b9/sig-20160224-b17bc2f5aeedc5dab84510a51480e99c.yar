rule sig_20160224_b17bc2f5aeedc5dab84510a51480e99c {
  meta:
    description = "datamaliciousorder - file 20160224_b17bc2f5aeedc5dab84510a51480e99c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8614e876883ab8192ce6ee42744a96b13df1d1e047ae1a461278ef95f424bc5"

  strings:
    $s1 = "        return WScript[polemicsZf](overweeningpNE);" fullword ascii
    $s2 = "    var cameoIyo = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s3 = "var explicatejyW = function(fructifyuV9) {" fullword ascii
    $s4 = "function btoa(stintb4D, dulcetCIJ, suppliantXkh, eschewTHR, vatFXl, citeg6J, levityriT, cantoRIJ, tenableYks, canondlX, meritewa" ascii
    $s5 = "function btoa(stintb4D, dulcetCIJ, suppliantXkh, eschewTHR, vatFXl, citeg6J, levityriT, cantoRIJ, tenableYks, canondlX, meritewa" ascii
    $s6 = "var incandescentRyR = function() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}