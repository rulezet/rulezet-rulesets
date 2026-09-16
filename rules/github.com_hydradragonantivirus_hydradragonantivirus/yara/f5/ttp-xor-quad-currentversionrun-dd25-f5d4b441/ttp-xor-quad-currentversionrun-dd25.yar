rule TTP_XOR_QUAD_CurrentVersionRun_dd25 {
  strings:
    $key_dd25 = { 8e 4a [2] aa 44 [2] 81 68 [2] af 4a [2] bb 51 [2] b4 4b [2] aa 56 [2] a8 57 [2] b3 51 [2] af 56 [2] b3 79 }

  condition:
    any of them
}