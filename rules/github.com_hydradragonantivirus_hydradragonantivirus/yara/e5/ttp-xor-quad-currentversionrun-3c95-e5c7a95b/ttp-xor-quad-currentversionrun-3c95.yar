rule TTP_XOR_QUAD_CurrentVersionRun_3c95 {
  strings:
    $key_3c95 = { 6f fa [2] 4b f4 [2] 60 d8 [2] 4e fa [2] 5a e1 [2] 55 fb [2] 4b e6 [2] 49 e7 [2] 52 e1 [2] 4e e6 [2] 52 c9 }

  condition:
    any of them
}