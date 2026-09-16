rule TTP_XOR_QUAD_CurrentVersionRun_da87 {
  strings:
    $key_da87 = { 89 e8 [2] ad e6 [2] 86 ca [2] a8 e8 [2] bc f3 [2] b3 e9 [2] ad f4 [2] af f5 [2] b4 f3 [2] a8 f4 [2] b4 db }

  condition:
    any of them
}