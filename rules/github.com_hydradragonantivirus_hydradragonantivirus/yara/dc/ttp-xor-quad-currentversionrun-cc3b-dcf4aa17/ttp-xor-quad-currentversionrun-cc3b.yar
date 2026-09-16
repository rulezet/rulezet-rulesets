rule TTP_XOR_QUAD_CurrentVersionRun_cc3b {
  strings:
    $key_cc3b = { 9f 54 [2] bb 5a [2] 90 76 [2] be 54 [2] aa 4f [2] a5 55 [2] bb 48 [2] b9 49 [2] a2 4f [2] be 48 [2] a2 67 }

  condition:
    any of them
}