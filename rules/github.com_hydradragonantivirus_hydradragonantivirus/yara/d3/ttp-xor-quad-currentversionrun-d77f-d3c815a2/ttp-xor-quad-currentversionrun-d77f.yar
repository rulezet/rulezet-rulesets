rule TTP_XOR_QUAD_CurrentVersionRun_d77f {
  strings:
    $key_d77f = { 84 10 [2] a0 1e [2] 8b 32 [2] a5 10 [2] b1 0b [2] be 11 [2] a0 0c [2] a2 0d [2] b9 0b [2] a5 0c [2] b9 23 }

  condition:
    any of them
}