rule TTP_XOR_QUAD_CurrentVersionRun_cc44 {
  strings:
    $key_cc44 = { 9f 2b [2] bb 25 [2] 90 09 [2] be 2b [2] aa 30 [2] a5 2a [2] bb 37 [2] b9 36 [2] a2 30 [2] be 37 [2] a2 18 }

  condition:
    any of them
}