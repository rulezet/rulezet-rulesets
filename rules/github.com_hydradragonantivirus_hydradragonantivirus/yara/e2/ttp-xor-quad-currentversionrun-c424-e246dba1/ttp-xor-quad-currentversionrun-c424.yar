rule TTP_XOR_QUAD_CurrentVersionRun_c424 {
  strings:
    $key_c424 = { 97 4b [2] b3 45 [2] 98 69 [2] b6 4b [2] a2 50 [2] ad 4a [2] b3 57 [2] b1 56 [2] aa 50 [2] b6 57 [2] aa 78 }

  condition:
    any of them
}