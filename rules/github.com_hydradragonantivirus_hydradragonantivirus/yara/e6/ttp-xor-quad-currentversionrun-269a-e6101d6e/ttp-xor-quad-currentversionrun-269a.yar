rule TTP_XOR_QUAD_CurrentVersionRun_269a {
  strings:
    $key_269a = { 75 f5 [2] 51 fb [2] 7a d7 [2] 54 f5 [2] 40 ee [2] 4f f4 [2] 51 e9 [2] 53 e8 [2] 48 ee [2] 54 e9 [2] 48 c6 }

  condition:
    any of them
}