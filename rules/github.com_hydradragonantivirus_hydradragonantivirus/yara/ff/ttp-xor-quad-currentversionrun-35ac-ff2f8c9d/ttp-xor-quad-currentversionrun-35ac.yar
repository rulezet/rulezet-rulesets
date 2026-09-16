rule TTP_XOR_QUAD_CurrentVersionRun_35ac {
  strings:
    $key_35ac = { 66 c3 [2] 42 cd [2] 69 e1 [2] 47 c3 [2] 53 d8 [2] 5c c2 [2] 42 df [2] 40 de [2] 5b d8 [2] 47 df [2] 5b f0 }

  condition:
    any of them
}