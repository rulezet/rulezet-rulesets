rule TTP_XOR_QUAD_CurrentVersionRun_dd17 {
  strings:
    $key_dd17 = { 8e 78 [2] aa 76 [2] 81 5a [2] af 78 [2] bb 63 [2] b4 79 [2] aa 64 [2] a8 65 [2] b3 63 [2] af 64 [2] b3 4b }

  condition:
    any of them
}