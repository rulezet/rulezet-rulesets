rule TTP_XOR_QUAD_CurrentVersionRun_198b {
  strings:
    $key_198b = { 4a e4 [2] 6e ea [2] 45 c6 [2] 6b e4 [2] 7f ff [2] 70 e5 [2] 6e f8 [2] 6c f9 [2] 77 ff [2] 6b f8 [2] 77 d7 }

  condition:
    any of them
}