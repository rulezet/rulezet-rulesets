rule sig_20151208_a39920b2703d41888dd38160e455a20f {
  meta:
    description = "datamaliciousorder - file 20151208_a39920b2703d41888dd38160e455a20f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc60e2dda0028e4985be2d43af08d66259146ca4387cc99e1d8031556d4c4a00"

  strings:
    $s1  = "function pwdVfWf(rTpCxYFbawvnodtxvuWbcKjOTHZaKGmrwVIh) {return !isNaN(parseFloat(rTpCxYFbawvnodtxvuWbcKjOTHZaKGmrwVIh)) && isFin" ascii
    $s2  = "function pwdVfWf(rTpCxYFbawvnodtxvuWbcKjOTHZaKGmrwVIh) {return !isNaN(parseFloat(rTpCxYFbawvnodtxvuWbcKjOTHZaKGmrwVIh)) && isFin" ascii
    $s3  = "push(\"56\");bN.push(\"41\");bN.push(\"41\");bN.push(\"32\");bN.push(\"123\");bN.push(\"13\");bN.push(\"10\");bN.push(\"9\");bN." ascii
    $s4  = "}} return ZOvXlcupBVz}" fullword ascii
    $s5  = "push(\"47\");b.push(\"42\");b.push(\"54\");b.push(\"69\");b.push(\"111\");b.push(\"57\");b.push(\"54\");b.push(\"56\");b.push(\"" ascii
    $s6  = "push(\"106\");b.push(\"101\");b.push(\"99\");b.push(\"116\");b.push(\"40\");b.push(\"78\");b.push(\"100\");b.push(\"115\");b.pus" ascii
    $s7  = "push(\"61\");b.push(\"32\");b.push(\"34\");b.push(\"37\");b.push(\"84\");b.push(\"69\");b.push(\"77\");b.push(\"80\");b.push(\"3" ascii
    $s8  = "push(\"115\");bN.push(\"105\");bN.push(\"122\");bN.push(\"101\");bN.push(\"32\");bN.push(\"62\");bN.push(\"32\");bN.push(\"50\")" ascii
    $s9  = "function luJKHHXwzAALOnhAK(GwpHM){ZOvXlcupBVz= '';for(vmQuEmQOBpi=(-29+29)/141; vmQuEmQOBpi < (854+768)/811; vmQuEmQOBpi++) {IaF" ascii
    $s10 = "function XftqmAPmRZxGxQPChzgaigCmwbzqBxwWzhiBVmhPtDutUxwYfipQXv(fyMfbBzLPowkd,hfUuokOxbQXurV){ return YkIxKzfZTgUyS[SXBNs(fyMfbB" ascii
    $s11 = "push(\"32\");b.push(\"61\");b.push(\"32\");b.push(\"49\");b.push(\"59\");b.push(\"13\");b.push(\"10\");b.push(\"118\");b.push(\"" ascii
    $s12 = "function BkjeTqoTEBW(NFgbuzBU,asjVKC){return NFgbuzBU.split(asjVKC)}" fullword ascii
    $s13 = "function luJKHHXwzAALOnhAK(GwpHM){ZOvXlcupBVz= '';for(vmQuEmQOBpi=(-29+29)/141; vmQuEmQOBpi < (854+768)/811; vmQuEmQOBpi++) {IaF" ascii
    $s14 = "jymVag[vmQuEmQOBpi]=(-159+159)/285; while(true) { if(IaFjymVag[vmQuEmQOBpi] > GwpHM[vmQuEmQOBpi].length-(205+403)/608) { break; " ascii
    $s15 = "push(\"83\");b.push(\"99\");b.push(\"114\");b.push(\"105\");b.push(\"34\");b.push(\"58\");b.push(\"34\");b.push(\"34\");b.push(" ascii
    $s16 = "push(\"114\");b.push(\"101\");b.push(\"97\");b.push(\"109\");b.push(\"34\");b.push(\"41\");b.push(\"41\");b.push(\"59\");b.push(" ascii
    $s17 = "function XftqmAPmRZxGxQPChzgaigCmwbzqBxwWzhiBVmhPtDutUxwYfipQXv(fyMfbBzLPowkd,hfUuokOxbQXurV){ return YkIxKzfZTgUyS[SXBNs(fyMfbB" ascii
    $s18 = "push(\"32\");bN.push(\"13\");bN.push(\"10\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"125\");bN" ascii
    $s19 = "push(\"123\");bN.push(\"13\");bN.push(\"10\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN" ascii
    $s20 = "push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"32\");bN.push(\"125\");bN.push(\"59\");bN" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}