rule TTP_XOR_QUAD_CurrentVersionRun_0d63 {
  strings:
    $key_0d63 = { 5e 0c [2] 7a 02 [2] 51 2e [2] 7f 0c [2] 6b 17 [2] 64 0d [2] 7a 10 [2] 78 11 [2] 63 17 [2] 7f 10 [2] 63 3f }

  condition:
    any of them
}