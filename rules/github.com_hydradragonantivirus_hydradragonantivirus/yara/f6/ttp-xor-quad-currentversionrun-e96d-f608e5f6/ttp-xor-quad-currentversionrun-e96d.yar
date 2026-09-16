rule TTP_XOR_QUAD_CurrentVersionRun_e96d {
  strings:
    $key_e96d = { ba 02 [2] 9e 0c [2] b5 20 [2] 9b 02 [2] 8f 19 [2] 80 03 [2] 9e 1e [2] 9c 1f [2] 87 19 [2] 9b 1e [2] 87 31 }

  condition:
    any of them
}