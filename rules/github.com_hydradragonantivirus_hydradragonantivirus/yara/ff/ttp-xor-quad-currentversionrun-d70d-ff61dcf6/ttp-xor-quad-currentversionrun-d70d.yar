rule TTP_XOR_QUAD_CurrentVersionRun_d70d {
  strings:
    $key_d70d = { 84 62 [2] a0 6c [2] 8b 40 [2] a5 62 [2] b1 79 [2] be 63 [2] a0 7e [2] a2 7f [2] b9 79 [2] a5 7e [2] b9 51 }

  condition:
    any of them
}