rule TTP_XOR_QUAD_CurrentVersionRun_f89b {
  strings:
    $key_f89b = { ab f4 [2] 8f fa [2] a4 d6 [2] 8a f4 [2] 9e ef [2] 91 f5 [2] 8f e8 [2] 8d e9 [2] 96 ef [2] 8a e8 [2] 96 c7 }

  condition:
    any of them
}