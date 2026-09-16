rule TTP_XOR_QUAD_CurrentVersionRun_dd15 {
  strings:
    $key_dd15 = { 8e 7a [2] aa 74 [2] 81 58 [2] af 7a [2] bb 61 [2] b4 7b [2] aa 66 [2] a8 67 [2] b3 61 [2] af 66 [2] b3 49 }

  condition:
    any of them
}