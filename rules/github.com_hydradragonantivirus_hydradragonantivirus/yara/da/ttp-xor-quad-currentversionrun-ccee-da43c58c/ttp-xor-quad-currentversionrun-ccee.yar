rule TTP_XOR_QUAD_CurrentVersionRun_ccee {
  strings:
    $key_ccee = { 9f 81 [2] bb 8f [2] 90 a3 [2] be 81 [2] aa 9a [2] a5 80 [2] bb 9d [2] b9 9c [2] a2 9a [2] be 9d [2] a2 b2 }

  condition:
    any of them
}