rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_22314dccf19b_723 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_ec2541ade561a4750092fda52be6f269.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash4       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash5       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash6       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash7       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash8       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash9       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"
    hash10      = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash11      = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"
    hash12      = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = "f000(){return \"DNa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"G" ascii
    $s2  = "rn \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(f" ascii
    $s3  = "(function f000(){return \"Br\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){re" ascii
    $s4  = "\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s5  = "n \"Iq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s6  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return" ascii
    $s7  = "return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(" ascii
    $s8  = "return \"ZGq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s9  = "Ij\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s10 = "\"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(functi" ascii
    $s11 = "\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";})(),(function f" ascii
    $s12 = "(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s13 = "nction f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s14 = "unction f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s15 = "on f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s16 = " \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(fun" ascii
    $s17 = "{return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s18 = "\"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s19 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";" ascii
    $s20 = "f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}