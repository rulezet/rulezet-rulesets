rule TTP_XOR_QUAD_CurrentVersionRun_e97f {
  strings:
    $key_e97f = { ba 10 [2] 9e 1e [2] b5 32 [2] 9b 10 [2] 8f 0b [2] 80 11 [2] 9e 0c [2] 9c 0d [2] 87 0b [2] 9b 0c [2] 87 23 }

  condition:
    any of them
}