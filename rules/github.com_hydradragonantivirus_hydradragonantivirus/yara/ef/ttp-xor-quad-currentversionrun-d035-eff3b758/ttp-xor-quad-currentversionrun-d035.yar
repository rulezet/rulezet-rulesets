rule TTP_XOR_QUAD_CurrentVersionRun_d035 {
  strings:
    $key_d035 = { 83 5a [2] a7 54 [2] 8c 78 [2] a2 5a [2] b6 41 [2] b9 5b [2] a7 46 [2] a5 47 [2] be 41 [2] a2 46 [2] be 69 }

  condition:
    any of them
}