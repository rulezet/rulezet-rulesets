rule TTP_XOR_QUAD_CurrentVersionRun_0d23 {
  strings:
    $key_0d23 = { 5e 4c [2] 7a 42 [2] 51 6e [2] 7f 4c [2] 6b 57 [2] 64 4d [2] 7a 50 [2] 78 51 [2] 63 57 [2] 7f 50 [2] 63 7f }

  condition:
    any of them
}