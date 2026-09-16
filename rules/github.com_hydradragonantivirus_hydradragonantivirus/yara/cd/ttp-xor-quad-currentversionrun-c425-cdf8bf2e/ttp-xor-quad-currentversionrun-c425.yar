rule TTP_XOR_QUAD_CurrentVersionRun_c425 {
  strings:
    $key_c425 = { 97 4a [2] b3 44 [2] 98 68 [2] b6 4a [2] a2 51 [2] ad 4b [2] b3 56 [2] b1 57 [2] aa 51 [2] b6 56 [2] aa 79 }

  condition:
    any of them
}