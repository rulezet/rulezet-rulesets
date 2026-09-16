rule TTP_XOR_QUAD_CurrentVersionRun_0d54 {
  strings:
    $key_0d54 = { 5e 3b [2] 7a 35 [2] 51 19 [2] 7f 3b [2] 6b 20 [2] 64 3a [2] 7a 27 [2] 78 26 [2] 63 20 [2] 7f 27 [2] 63 08 }

  condition:
    any of them
}