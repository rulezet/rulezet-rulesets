rule TTP_XOR_QUAD_CurrentVersionRun_da84 {
  strings:
    $key_da84 = { 89 eb [2] ad e5 [2] 86 c9 [2] a8 eb [2] bc f0 [2] b3 ea [2] ad f7 [2] af f6 [2] b4 f0 [2] a8 f7 [2] b4 d8 }

  condition:
    any of them
}