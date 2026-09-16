rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_e1835bc92c46_2963 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s2 = "){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})()" ascii
    $s3 = ",(function f000(){return \"Ot\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s4 = "\"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s5 = "on f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s6 = "n f000(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"" ascii
    $s7 = "on f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}