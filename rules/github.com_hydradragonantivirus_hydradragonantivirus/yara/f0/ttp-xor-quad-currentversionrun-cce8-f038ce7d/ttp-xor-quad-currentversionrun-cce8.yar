rule TTP_XOR_QUAD_CurrentVersionRun_cce8 {
  strings:
    $key_cce8 = { 9f 87 [2] bb 89 [2] 90 a5 [2] be 87 [2] aa 9c [2] a5 86 [2] bb 9b [2] b9 9a [2] a2 9c [2] be 9b [2] a2 b4 }

  condition:
    any of them
}