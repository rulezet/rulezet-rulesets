rule TTP_XOR_QUAD_CurrentVersionRun_27ac {
  strings:
    $key_27ac = { 74 c3 [2] 50 cd [2] 7b e1 [2] 55 c3 [2] 41 d8 [2] 4e c2 [2] 50 df [2] 52 de [2] 49 d8 [2] 55 df [2] 49 f0 }

  condition:
    any of them
}