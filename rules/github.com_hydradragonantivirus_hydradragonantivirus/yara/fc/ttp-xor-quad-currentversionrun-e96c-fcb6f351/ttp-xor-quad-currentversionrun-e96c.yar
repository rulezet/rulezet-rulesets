rule TTP_XOR_QUAD_CurrentVersionRun_e96c {
  strings:
    $key_e96c = { ba 03 [2] 9e 0d [2] b5 21 [2] 9b 03 [2] 8f 18 [2] 80 02 [2] 9e 1f [2] 9c 1e [2] 87 18 [2] 9b 1f [2] 87 30 }

  condition:
    any of them
}