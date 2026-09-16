rule TTP_XOR_QUAD_CurrentVersionRun_57ac {
  strings:
    $key_57ac = { 04 c3 [2] 20 cd [2] 0b e1 [2] 25 c3 [2] 31 d8 [2] 3e c2 [2] 20 df [2] 22 de [2] 39 d8 [2] 25 df [2] 39 f0 }

  condition:
    any of them
}