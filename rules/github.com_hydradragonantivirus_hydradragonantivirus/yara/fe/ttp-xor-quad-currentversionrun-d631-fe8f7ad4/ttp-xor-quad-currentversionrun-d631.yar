rule TTP_XOR_QUAD_CurrentVersionRun_d631 {
  strings:
    $key_d631 = { 85 5e [2] a1 50 [2] 8a 7c [2] a4 5e [2] b0 45 [2] bf 5f [2] a1 42 [2] a3 43 [2] b8 45 [2] a4 42 [2] b8 6d }

  condition:
    any of them
}