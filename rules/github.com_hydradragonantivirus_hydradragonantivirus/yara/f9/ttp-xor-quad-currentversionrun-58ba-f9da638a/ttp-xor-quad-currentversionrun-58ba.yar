rule TTP_XOR_QUAD_CurrentVersionRun_58ba {
  strings:
    $key_58ba = { 0b d5 [2] 2f db [2] 04 f7 [2] 2a d5 [2] 3e ce [2] 31 d4 [2] 2f c9 [2] 2d c8 [2] 36 ce [2] 2a c9 [2] 36 e6 }

  condition:
    any of them
}