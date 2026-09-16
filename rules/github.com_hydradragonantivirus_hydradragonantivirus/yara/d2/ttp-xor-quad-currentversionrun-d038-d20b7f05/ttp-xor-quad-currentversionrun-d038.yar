rule TTP_XOR_QUAD_CurrentVersionRun_d038 {
  strings:
    $key_d038 = { 83 57 [2] a7 59 [2] 8c 75 [2] a2 57 [2] b6 4c [2] b9 56 [2] a7 4b [2] a5 4a [2] be 4c [2] a2 4b [2] be 64 }

  condition:
    any of them
}