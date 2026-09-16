rule TTP_XOR_QUAD_CurrentVersionRun_e920 {
  strings:
    $key_e920 = { ba 4f [2] 9e 41 [2] b5 6d [2] 9b 4f [2] 8f 54 [2] 80 4e [2] 9e 53 [2] 9c 52 [2] 87 54 [2] 9b 53 [2] 87 7c }

  condition:
    any of them
}