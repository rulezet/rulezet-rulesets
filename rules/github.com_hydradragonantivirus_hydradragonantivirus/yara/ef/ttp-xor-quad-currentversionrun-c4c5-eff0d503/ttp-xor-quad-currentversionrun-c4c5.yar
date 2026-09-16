rule TTP_XOR_QUAD_CurrentVersionRun_c4c5 {
  strings:
    $key_c4c5 = { 97 aa [2] b3 a4 [2] 98 88 [2] b6 aa [2] a2 b1 [2] ad ab [2] b3 b6 [2] b1 b7 [2] aa b1 [2] b6 b6 [2] aa 99 }

  condition:
    any of them
}