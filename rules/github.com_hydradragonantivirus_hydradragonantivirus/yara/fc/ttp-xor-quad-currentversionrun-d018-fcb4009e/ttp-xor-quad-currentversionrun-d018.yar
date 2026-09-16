rule TTP_XOR_QUAD_CurrentVersionRun_d018 {
  strings:
    $key_d018 = { 83 77 [2] a7 79 [2] 8c 55 [2] a2 77 [2] b6 6c [2] b9 76 [2] a7 6b [2] a5 6a [2] be 6c [2] a2 6b [2] be 44 }

  condition:
    any of them
}