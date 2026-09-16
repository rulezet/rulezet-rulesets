rule TTP_XOR_QUAD_CurrentVersionRun_ace6 {
  strings:
    $key_ace6 = { ff 89 [2] db 87 [2] f0 ab [2] de 89 [2] ca 92 [2] c5 88 [2] db 95 [2] d9 94 [2] c2 92 [2] de 95 [2] c2 ba }

  condition:
    any of them
}