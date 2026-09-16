rule TTP_XOR_QUAD_CurrentVersionRun_d72c {
  strings:
    $key_d72c = { 84 43 [2] a0 4d [2] 8b 61 [2] a5 43 [2] b1 58 [2] be 42 [2] a0 5f [2] a2 5e [2] b9 58 [2] a5 5f [2] b9 70 }

  condition:
    any of them
}