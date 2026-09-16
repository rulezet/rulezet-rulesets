rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_2fddda42e591_4734 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash3       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash4       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash5       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash6       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1 = "n \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s2 = "0(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";" ascii
    $s3 = "j\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function" ascii
    $s4 = "tion f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s5 = "nction f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}