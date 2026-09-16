rule TTP_XOR_QUAD_CurrentVersionRun_6c95 {
  strings:
    $key_6c95 = { 3f fa [2] 1b f4 [2] 30 d8 [2] 1e fa [2] 0a e1 [2] 05 fb [2] 1b e6 [2] 19 e7 [2] 02 e1 [2] 1e e6 [2] 02 c9 }

  condition:
    any of them
}