rule TTP_XOR_QUAD_CurrentVersionRun_d77d {
  strings:
    $key_d77d = { 84 12 [2] a0 1c [2] 8b 30 [2] a5 12 [2] b1 09 [2] be 13 [2] a0 0e [2] a2 0f [2] b9 09 [2] a5 0e [2] b9 21 }

  condition:
    any of them
}