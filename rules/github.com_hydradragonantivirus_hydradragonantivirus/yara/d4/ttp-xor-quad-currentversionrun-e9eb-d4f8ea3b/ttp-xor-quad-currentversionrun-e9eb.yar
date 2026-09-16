rule TTP_XOR_QUAD_CurrentVersionRun_e9eb {
  strings:
    $key_e9eb = { ba 84 [2] 9e 8a [2] b5 a6 [2] 9b 84 [2] 8f 9f [2] 80 85 [2] 9e 98 [2] 9c 99 [2] 87 9f [2] 9b 98 [2] 87 b7 }

  condition:
    any of them
}