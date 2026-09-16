rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_382a0f9b1ae6_845 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1  = "rn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s2  = "n f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MB" ascii
    $s3  = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx" ascii
    $s4  = "{return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})()" ascii
    $s5  = "n\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(functio" ascii
    $s6  = "ction f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s7  = "on f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s8  = "000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s9  = ",(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000()" ascii
    $s10 = "rn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s11 = "KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(functio" ascii
    $s12 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";" ascii
    $s13 = "(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s14 = "){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})" ascii
    $s15 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s16 = "Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function" ascii
    $s17 = "n f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s18 = "function f000(){return \"MMz\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s19 = "turn \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})()" ascii
    $s20 = "\"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}