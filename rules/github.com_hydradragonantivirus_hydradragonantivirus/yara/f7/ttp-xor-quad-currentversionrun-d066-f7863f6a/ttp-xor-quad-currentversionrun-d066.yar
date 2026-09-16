rule TTP_XOR_QUAD_CurrentVersionRun_d066 {
  strings:
    $key_d066 = { 83 09 [2] a7 07 [2] 8c 2b [2] a2 09 [2] b6 12 [2] b9 08 [2] a7 15 [2] a5 14 [2] be 12 [2] a2 15 [2] be 3a }

  condition:
    any of them
}