rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_ccabe4fce99c_1535 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1  = "Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s2  = " f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MM" ascii
    $s3  = "{return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})" ascii
    $s4  = "(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(function f000(){re" ascii
    $s5  = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(f" ascii
    $s6  = ",(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){" ascii
    $s7  = " f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQ" ascii
    $s8  = " \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s9  = "tion f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "tion f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s11 = "turn \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s12 = "f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DYx" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}