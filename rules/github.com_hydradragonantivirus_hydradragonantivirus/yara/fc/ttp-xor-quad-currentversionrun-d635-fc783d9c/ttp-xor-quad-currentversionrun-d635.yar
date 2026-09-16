rule TTP_XOR_QUAD_CurrentVersionRun_d635 {
  strings:
    $key_d635 = { 85 5a [2] a1 54 [2] 8a 78 [2] a4 5a [2] b0 41 [2] bf 5b [2] a1 46 [2] a3 47 [2] b8 41 [2] a4 46 [2] b8 69 }

  condition:
    any of them
}