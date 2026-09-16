rule TTP_XOR_QUAD_CurrentVersionRun_cc10 {
  strings:
    $key_cc10 = { 9f 7f [2] bb 71 [2] 90 5d [2] be 7f [2] aa 64 [2] a5 7e [2] bb 63 [2] b9 62 [2] a2 64 [2] be 63 [2] a2 4c }

  condition:
    any of them
}