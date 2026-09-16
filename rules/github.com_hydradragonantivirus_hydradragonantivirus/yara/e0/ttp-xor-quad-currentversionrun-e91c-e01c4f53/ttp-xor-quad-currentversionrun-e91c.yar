rule TTP_XOR_QUAD_CurrentVersionRun_e91c {
  strings:
    $key_e91c = { ba 73 [2] 9e 7d [2] b5 51 [2] 9b 73 [2] 8f 68 [2] 80 72 [2] 9e 6f [2] 9c 6e [2] 87 68 [2] 9b 6f [2] 87 40 }

  condition:
    any of them
}