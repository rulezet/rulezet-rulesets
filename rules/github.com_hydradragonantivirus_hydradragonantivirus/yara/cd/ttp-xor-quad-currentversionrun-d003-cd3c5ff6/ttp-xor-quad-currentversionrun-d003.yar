rule TTP_XOR_QUAD_CurrentVersionRun_d003 {
  strings:
    $key_d003 = { 83 6c [2] a7 62 [2] 8c 4e [2] a2 6c [2] b6 77 [2] b9 6d [2] a7 70 [2] a5 71 [2] be 77 [2] a2 70 [2] be 5f }

  condition:
    any of them
}