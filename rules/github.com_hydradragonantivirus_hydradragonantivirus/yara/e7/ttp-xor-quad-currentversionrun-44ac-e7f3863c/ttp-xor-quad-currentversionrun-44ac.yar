rule TTP_XOR_QUAD_CurrentVersionRun_44ac {
  strings:
    $key_44ac = { 17 c3 [2] 33 cd [2] 18 e1 [2] 36 c3 [2] 22 d8 [2] 2d c2 [2] 33 df [2] 31 de [2] 2a d8 [2] 36 df [2] 2a f0 }

  condition:
    any of them
}