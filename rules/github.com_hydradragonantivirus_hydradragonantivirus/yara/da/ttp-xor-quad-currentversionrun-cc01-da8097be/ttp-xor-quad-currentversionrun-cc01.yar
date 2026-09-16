rule TTP_XOR_QUAD_CurrentVersionRun_cc01 {
  strings:
    $key_cc01 = { 9f 6e [2] bb 60 [2] 90 4c [2] be 6e [2] aa 75 [2] a5 6f [2] bb 72 [2] b9 73 [2] a2 75 [2] be 72 [2] a2 5d }

  condition:
    any of them
}