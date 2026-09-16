rule TTP_XOR_QUAD_CurrentVersionRun_eac9 {
  strings:
    $key_eac9 = { b9 a6 [2] 9d a8 [2] b6 84 [2] 98 a6 [2] 8c bd [2] 83 a7 [2] 9d ba [2] 9f bb [2] 84 bd [2] 98 ba [2] 84 95 }

  condition:
    any of them
}