rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_25c11e2eab44_724 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash3       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash4       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash5       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash6       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash7       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash8       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1  = "ion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return" ascii
    $s2  = "})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s3  = "})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii
    $s4  = "0(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Br\"" ascii
    $s5  = "nction f000(){return \"ZFe\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s6  = "rn \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s7  = "),(function f000(){return \"Nx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s8  = ",(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000()" ascii
    $s9  = "urn \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s10 = "f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br" ascii
    $s11 = "return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(" ascii
    $s12 = "\"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s13 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MOc\";" ascii
    $s14 = "f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"SG" ascii
    $s15 = "(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s16 = "GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s17 = "00(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";" ascii
    $s18 = "})(),(function f000(){return \"DYs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s19 = "ion f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return " ascii
    $s20 = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}