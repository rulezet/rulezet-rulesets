rule TTP_XOR_QUAD_CurrentVersionRun_c51d {
  strings:
    $key_c51d = { 96 72 [2] b2 7c [2] 99 50 [2] b7 72 [2] a3 69 [2] ac 73 [2] b2 6e [2] b0 6f [2] ab 69 [2] b7 6e [2] ab 41 }

  condition:
    any of them
}