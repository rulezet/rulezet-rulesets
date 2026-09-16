rule TTP_XOR_QUAD_CurrentVersionRun_d004 {
  strings:
    $key_d004 = { 83 6b [2] a7 65 [2] 8c 49 [2] a2 6b [2] b6 70 [2] b9 6a [2] a7 77 [2] a5 76 [2] be 70 [2] a2 77 [2] be 58 }

  condition:
    any of them
}