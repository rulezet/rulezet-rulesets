rule TTP_XOR_QUAD_CurrentVersionRun_c330 {
  strings:
    $key_c330 = { 90 5f [2] b4 51 [2] 9f 7d [2] b1 5f [2] a5 44 [2] aa 5e [2] b4 43 [2] b6 42 [2] ad 44 [2] b1 43 [2] ad 6c }

  condition:
    any of them
}