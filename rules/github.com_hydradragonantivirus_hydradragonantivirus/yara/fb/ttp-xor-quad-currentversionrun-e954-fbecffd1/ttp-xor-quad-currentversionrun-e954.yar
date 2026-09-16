rule TTP_XOR_QUAD_CurrentVersionRun_e954 {
  strings:
    $key_e954 = { ba 3b [2] 9e 35 [2] b5 19 [2] 9b 3b [2] 8f 20 [2] 80 3a [2] 9e 27 [2] 9c 26 [2] 87 20 [2] 9b 27 [2] 87 08 }

  condition:
    any of them
}