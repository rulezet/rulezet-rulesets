rule TTP_XOR_QUAD_CurrentVersionRun_7753 {
  strings:
    $key_7753 = { 24 3c [2] 00 32 [2] 2b 1e [2] 05 3c [2] 11 27 [2] 1e 3d [2] 00 20 [2] 02 21 [2] 19 27 [2] 05 20 [2] 19 0f }

  condition:
    any of them
}