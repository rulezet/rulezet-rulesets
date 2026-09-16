rule TTP_XOR_QUAD_CurrentVersionRun_c446 {
  strings:
    $key_c446 = { 97 29 [2] b3 27 [2] 98 0b [2] b6 29 [2] a2 32 [2] ad 28 [2] b3 35 [2] b1 34 [2] aa 32 [2] b6 35 [2] aa 1a }

  condition:
    any of them
}