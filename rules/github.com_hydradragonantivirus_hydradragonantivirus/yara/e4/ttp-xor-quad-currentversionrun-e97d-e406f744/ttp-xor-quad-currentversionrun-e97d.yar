rule TTP_XOR_QUAD_CurrentVersionRun_e97d {
  strings:
    $key_e97d = { ba 12 [2] 9e 1c [2] b5 30 [2] 9b 12 [2] 8f 09 [2] 80 13 [2] 9e 0e [2] 9c 0f [2] 87 09 [2] 9b 0e [2] 87 21 }

  condition:
    any of them
}