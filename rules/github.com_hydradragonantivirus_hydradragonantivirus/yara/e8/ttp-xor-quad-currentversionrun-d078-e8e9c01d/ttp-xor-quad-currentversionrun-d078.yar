rule TTP_XOR_QUAD_CurrentVersionRun_d078 {
  strings:
    $key_d078 = { 83 17 [2] a7 19 [2] 8c 35 [2] a2 17 [2] b6 0c [2] b9 16 [2] a7 0b [2] a5 0a [2] be 0c [2] a2 0b [2] be 24 }

  condition:
    any of them
}