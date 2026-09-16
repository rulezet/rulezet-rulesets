rule TTP_XOR_QUAD_CurrentVersionRun_eee6 {
  strings:
    $key_eee6 = { bd 89 [2] 99 87 [2] b2 ab [2] 9c 89 [2] 88 92 [2] 87 88 [2] 99 95 [2] 9b 94 [2] 80 92 [2] 9c 95 [2] 80 ba }

  condition:
    any of them
}