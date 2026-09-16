rule TTP_XOR_QUAD_CurrentVersionRun_d008 {
  strings:
    $key_d008 = { 83 67 [2] a7 69 [2] 8c 45 [2] a2 67 [2] b6 7c [2] b9 66 [2] a7 7b [2] a5 7a [2] be 7c [2] a2 7b [2] be 54 }

  condition:
    any of them
}