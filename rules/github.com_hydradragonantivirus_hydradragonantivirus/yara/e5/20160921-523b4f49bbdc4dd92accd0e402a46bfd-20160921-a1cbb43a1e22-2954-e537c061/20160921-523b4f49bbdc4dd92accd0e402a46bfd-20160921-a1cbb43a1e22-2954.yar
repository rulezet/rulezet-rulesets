rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_a1cbb43a1e22_2954 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash4       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"
    hash5       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash6       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s2 = "urn \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()," ascii
    $s3 = "on f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s4 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f0" ascii
    $s5 = "on f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s6 = "f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Q" ascii
    $s7 = "eturn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}