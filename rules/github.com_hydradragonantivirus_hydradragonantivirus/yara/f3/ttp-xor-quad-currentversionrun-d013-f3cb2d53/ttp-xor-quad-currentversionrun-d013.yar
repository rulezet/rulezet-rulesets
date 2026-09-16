rule TTP_XOR_QUAD_CurrentVersionRun_d013 {
  strings:
    $key_d013 = { 83 7c [2] a7 72 [2] 8c 5e [2] a2 7c [2] b6 67 [2] b9 7d [2] a7 60 [2] a5 61 [2] be 67 [2] a2 60 [2] be 4f }

  condition:
    any of them
}