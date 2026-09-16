rule TTP_XOR_QUAD_CurrentVersionRun_eeb6 {
  strings:
    $key_eeb6 = { bd d9 [2] 99 d7 [2] b2 fb [2] 9c d9 [2] 88 c2 [2] 87 d8 [2] 99 c5 [2] 9b c4 [2] 80 c2 [2] 9c c5 [2] 80 ea }

  condition:
    any of them
}