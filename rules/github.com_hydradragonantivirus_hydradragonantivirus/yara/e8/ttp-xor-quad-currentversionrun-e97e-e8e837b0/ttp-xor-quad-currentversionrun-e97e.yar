rule TTP_XOR_QUAD_CurrentVersionRun_e97e {
  strings:
    $key_e97e = { ba 11 [2] 9e 1f [2] b5 33 [2] 9b 11 [2] 8f 0a [2] 80 10 [2] 9e 0d [2] 9c 0c [2] 87 0a [2] 9b 0d [2] 87 22 }

  condition:
    any of them
}