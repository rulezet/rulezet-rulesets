rule TTP_XOR_QUAD_CurrentVersionRun_d72d {
  strings:
    $key_d72d = { 84 42 [2] a0 4c [2] 8b 60 [2] a5 42 [2] b1 59 [2] be 43 [2] a0 5e [2] a2 5f [2] b9 59 [2] a5 5e [2] b9 71 }

  condition:
    any of them
}