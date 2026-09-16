rule TTP_XOR_QUAD_CurrentVersionRun_d71e {
  strings:
    $key_d71e = { 84 71 [2] a0 7f [2] 8b 53 [2] a5 71 [2] b1 6a [2] be 70 [2] a0 6d [2] a2 6c [2] b9 6a [2] a5 6d [2] b9 42 }

  condition:
    any of them
}