rule TTP_XOR_QUAD_CurrentVersionRun_d12c {
  strings:
    $key_d12c = { 82 43 [2] a6 4d [2] 8d 61 [2] a3 43 [2] b7 58 [2] b8 42 [2] a6 5f [2] a4 5e [2] bf 58 [2] a3 5f [2] bf 70 }

  condition:
    any of them
}