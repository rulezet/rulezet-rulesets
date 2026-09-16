rule TTP_XOR_QUAD_CurrentVersionRun_1330 {
  strings:
    $key_1330 = { 40 5f [2] 64 51 [2] 4f 7d [2] 61 5f [2] 75 44 [2] 7a 5e [2] 64 43 [2] 66 42 [2] 7d 44 [2] 61 43 [2] 7d 6c }

  condition:
    any of them
}