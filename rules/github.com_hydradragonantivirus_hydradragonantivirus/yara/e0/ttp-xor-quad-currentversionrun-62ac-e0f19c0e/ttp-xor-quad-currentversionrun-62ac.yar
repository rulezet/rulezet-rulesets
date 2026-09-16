rule TTP_XOR_QUAD_CurrentVersionRun_62ac {
  strings:
    $key_62ac = { 31 c3 [2] 15 cd [2] 3e e1 [2] 10 c3 [2] 04 d8 [2] 0b c2 [2] 15 df [2] 17 de [2] 0c d8 [2] 10 df [2] 0c f0 }

  condition:
    any of them
}