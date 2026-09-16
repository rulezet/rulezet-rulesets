rule TTP_XOR_QUAD_CurrentVersionRun_d701 {
  strings:
    $key_d701 = { 84 6e [2] a0 60 [2] 8b 4c [2] a5 6e [2] b1 75 [2] be 6f [2] a0 72 [2] a2 73 [2] b9 75 [2] a5 72 [2] b9 5d }

  condition:
    any of them
}