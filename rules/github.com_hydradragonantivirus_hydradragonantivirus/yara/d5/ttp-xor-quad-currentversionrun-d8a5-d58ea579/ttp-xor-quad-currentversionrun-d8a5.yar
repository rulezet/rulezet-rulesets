rule TTP_XOR_QUAD_CurrentVersionRun_d8a5 {
  strings:
    $key_d8a5 = { 8b ca [2] af c4 [2] 84 e8 [2] aa ca [2] be d1 [2] b1 cb [2] af d6 [2] ad d7 [2] b6 d1 [2] aa d6 [2] b6 f9 }

  condition:
    any of them
}