rule TTP_XOR_QUAD_CurrentVersionRun_1ac9 {
  strings:
    $key_1ac9 = { 49 a6 [2] 6d a8 [2] 46 84 [2] 68 a6 [2] 7c bd [2] 73 a7 [2] 6d ba [2] 6f bb [2] 74 bd [2] 68 ba [2] 74 95 }

  condition:
    any of them
}