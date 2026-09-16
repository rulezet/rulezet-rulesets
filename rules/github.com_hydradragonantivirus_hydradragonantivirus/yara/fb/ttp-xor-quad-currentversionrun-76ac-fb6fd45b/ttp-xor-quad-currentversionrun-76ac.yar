rule TTP_XOR_QUAD_CurrentVersionRun_76ac {
  strings:
    $key_76ac = { 25 c3 [2] 01 cd [2] 2a e1 [2] 04 c3 [2] 10 d8 [2] 1f c2 [2] 01 df [2] 03 de [2] 18 d8 [2] 04 df [2] 18 f0 }

  condition:
    any of them
}