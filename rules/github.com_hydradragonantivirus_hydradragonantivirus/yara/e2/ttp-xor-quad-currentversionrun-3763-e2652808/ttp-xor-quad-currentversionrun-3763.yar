rule TTP_XOR_QUAD_CurrentVersionRun_3763 {
  strings:
    $key_3763 = { 64 0c [2] 40 02 [2] 6b 2e [2] 45 0c [2] 51 17 [2] 5e 0d [2] 40 10 [2] 42 11 [2] 59 17 [2] 45 10 [2] 59 3f }

  condition:
    any of them
}