rule TTP_XOR_QUAD_CurrentVersionRun_d730 {
  strings:
    $key_d730 = { 84 5f [2] a0 51 [2] 8b 7d [2] a5 5f [2] b1 44 [2] be 5e [2] a0 43 [2] a2 42 [2] b9 44 [2] a5 43 [2] b9 6c }

  condition:
    any of them
}