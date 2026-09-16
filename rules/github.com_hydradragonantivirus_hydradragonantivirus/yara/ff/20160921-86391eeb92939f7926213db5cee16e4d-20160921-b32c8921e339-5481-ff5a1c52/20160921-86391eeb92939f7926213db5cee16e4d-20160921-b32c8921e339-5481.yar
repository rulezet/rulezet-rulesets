rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_b32c8921e339_5481 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "s\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2 = "(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s3 = " \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s4 = "{return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})" ascii
    $s5 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}