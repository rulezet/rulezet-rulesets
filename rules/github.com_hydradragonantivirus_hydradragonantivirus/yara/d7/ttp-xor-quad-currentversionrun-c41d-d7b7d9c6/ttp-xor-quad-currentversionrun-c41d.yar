rule TTP_XOR_QUAD_CurrentVersionRun_c41d {
  strings:
    $key_c41d = { 97 72 [2] b3 7c [2] 98 50 [2] b6 72 [2] a2 69 [2] ad 73 [2] b3 6e [2] b1 6f [2] aa 69 [2] b6 6e [2] aa 41 }

  condition:
    any of them
}