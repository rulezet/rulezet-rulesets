rule TTP_XOR_QUAD_CurrentVersionRun_cc66 {
  strings:
    $key_cc66 = { 9f 09 [2] bb 07 [2] 90 2b [2] be 09 [2] aa 12 [2] a5 08 [2] bb 15 [2] b9 14 [2] a2 12 [2] be 15 [2] a2 3a }

  condition:
    any of them
}