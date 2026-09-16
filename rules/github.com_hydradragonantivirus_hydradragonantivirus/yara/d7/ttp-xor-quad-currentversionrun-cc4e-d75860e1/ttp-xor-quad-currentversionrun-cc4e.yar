rule TTP_XOR_QUAD_CurrentVersionRun_cc4e {
  strings:
    $key_cc4e = { 9f 21 [2] bb 2f [2] 90 03 [2] be 21 [2] aa 3a [2] a5 20 [2] bb 3d [2] b9 3c [2] a2 3a [2] be 3d [2] a2 12 }

  condition:
    any of them
}