rule TTP_XOR_QUAD_CurrentVersionRun_cc5c {
  strings:
    $key_cc5c = { 9f 33 [2] bb 3d [2] 90 11 [2] be 33 [2] aa 28 [2] a5 32 [2] bb 2f [2] b9 2e [2] a2 28 [2] be 2f [2] a2 00 }

  condition:
    any of them
}