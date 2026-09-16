rule TTP_XOR_QUAD_CurrentVersionRun_dd77 {
  strings:
    $key_dd77 = { 8e 18 [2] aa 16 [2] 81 3a [2] af 18 [2] bb 03 [2] b4 19 [2] aa 04 [2] a8 05 [2] b3 03 [2] af 04 [2] b3 2b }

  condition:
    any of them
}