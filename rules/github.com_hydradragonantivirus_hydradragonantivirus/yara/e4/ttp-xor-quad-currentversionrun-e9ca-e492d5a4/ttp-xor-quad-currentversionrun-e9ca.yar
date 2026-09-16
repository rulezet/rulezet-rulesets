rule TTP_XOR_QUAD_CurrentVersionRun_e9ca {
  strings:
    $key_e9ca = { ba a5 [2] 9e ab [2] b5 87 [2] 9b a5 [2] 8f be [2] 80 a4 [2] 9e b9 [2] 9c b8 [2] 87 be [2] 9b b9 [2] 87 96 }

  condition:
    any of them
}