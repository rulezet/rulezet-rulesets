rule TTP_XOR_QUAD_CurrentVersionRun_cc6c {
  strings:
    $key_cc6c = { 9f 03 [2] bb 0d [2] 90 21 [2] be 03 [2] aa 18 [2] a5 02 [2] bb 1f [2] b9 1e [2] a2 18 [2] be 1f [2] a2 30 }

  condition:
    any of them
}