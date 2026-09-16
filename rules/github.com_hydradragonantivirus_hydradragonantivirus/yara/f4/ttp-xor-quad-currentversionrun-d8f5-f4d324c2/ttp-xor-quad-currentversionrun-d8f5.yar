rule TTP_XOR_QUAD_CurrentVersionRun_d8f5 {
  strings:
    $key_d8f5 = { 8b 9a [2] af 94 [2] 84 b8 [2] aa 9a [2] be 81 [2] b1 9b [2] af 86 [2] ad 87 [2] b6 81 [2] aa 86 [2] b6 a9 }

  condition:
    any of them
}