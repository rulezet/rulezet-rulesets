rule TTP_XOR_QUAD_CurrentVersionRun_d8b9 {
  strings:
    $key_d8b9 = { 8b d6 [2] af d8 [2] 84 f4 [2] aa d6 [2] be cd [2] b1 d7 [2] af ca [2] ad cb [2] b6 cd [2] aa ca [2] b6 e5 }

  condition:
    any of them
}