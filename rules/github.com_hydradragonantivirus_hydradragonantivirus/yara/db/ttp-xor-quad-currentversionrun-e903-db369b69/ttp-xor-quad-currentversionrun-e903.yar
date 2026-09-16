rule TTP_XOR_QUAD_CurrentVersionRun_e903 {
  strings:
    $key_e903 = { ba 6c [2] 9e 62 [2] b5 4e [2] 9b 6c [2] 8f 77 [2] 80 6d [2] 9e 70 [2] 9c 71 [2] 87 77 [2] 9b 70 [2] 87 5f }

  condition:
    any of them
}