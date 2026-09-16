rule TTP_XOR_QUAD_CurrentVersionRun_cc20 {
  strings:
    $key_cc20 = { 9f 4f [2] bb 41 [2] 90 6d [2] be 4f [2] aa 54 [2] a5 4e [2] bb 53 [2] b9 52 [2] a2 54 [2] be 53 [2] a2 7c }

  condition:
    any of them
}