rule TTP_XOR_QUAD_CurrentVersionRun_d048 {
  strings:
    $key_d048 = { 83 27 [2] a7 29 [2] 8c 05 [2] a2 27 [2] b6 3c [2] b9 26 [2] a7 3b [2] a5 3a [2] be 3c [2] a2 3b [2] be 14 }

  condition:
    any of them
}