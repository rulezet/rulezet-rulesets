rule TTP_XOR_QUAD_CurrentVersionRun_e965 {
  strings:
    $key_e965 = { ba 0a [2] 9e 04 [2] b5 28 [2] 9b 0a [2] 8f 11 [2] 80 0b [2] 9e 16 [2] 9c 17 [2] 87 11 [2] 9b 16 [2] 87 39 }

  condition:
    any of them
}