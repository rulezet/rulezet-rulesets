rule TTP_XOR_QUAD_CurrentVersionRun_e96a {
  strings:
    $key_e96a = { ba 05 [2] 9e 0b [2] b5 27 [2] 9b 05 [2] 8f 1e [2] 80 04 [2] 9e 19 [2] 9c 18 [2] 87 1e [2] 9b 19 [2] 87 36 }

  condition:
    any of them
}