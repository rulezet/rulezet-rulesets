rule TTP_XOR_QUAD_CurrentVersionRun_c620 {
  strings:
    $key_c620 = { 95 4f [2] b1 41 [2] 9a 6d [2] b4 4f [2] a0 54 [2] af 4e [2] b1 53 [2] b3 52 [2] a8 54 [2] b4 53 [2] a8 7c }

  condition:
    any of them
}