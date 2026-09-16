rule TTP_XOR_QUAD_CurrentVersionRun_65ac {
  strings:
    $key_65ac = { 36 c3 [2] 12 cd [2] 39 e1 [2] 17 c3 [2] 03 d8 [2] 0c c2 [2] 12 df [2] 10 de [2] 0b d8 [2] 17 df [2] 0b f0 }

  condition:
    any of them
}