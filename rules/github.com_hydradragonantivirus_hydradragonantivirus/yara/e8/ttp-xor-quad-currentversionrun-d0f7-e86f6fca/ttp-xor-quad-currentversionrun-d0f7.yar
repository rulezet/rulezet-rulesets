rule TTP_XOR_QUAD_CurrentVersionRun_d0f7 {
  strings:
    $key_d0f7 = { 83 98 [2] a7 96 [2] 8c ba [2] a2 98 [2] b6 83 [2] b9 99 [2] a7 84 [2] a5 85 [2] be 83 [2] a2 84 [2] be ab }

  condition:
    any of them
}