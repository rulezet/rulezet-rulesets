rule TTP_XOR_QUAD_CurrentVersionRun_4ac9 {
  strings:
    $key_4ac9 = { 19 a6 [2] 3d a8 [2] 16 84 [2] 38 a6 [2] 2c bd [2] 23 a7 [2] 3d ba [2] 3f bb [2] 24 bd [2] 38 ba [2] 24 95 }

  condition:
    any of them
}