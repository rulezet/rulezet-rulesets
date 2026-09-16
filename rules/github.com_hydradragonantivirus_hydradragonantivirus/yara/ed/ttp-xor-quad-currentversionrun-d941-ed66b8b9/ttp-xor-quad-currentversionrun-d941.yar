rule TTP_XOR_QUAD_CurrentVersionRun_d941 {
  strings:
    $key_d941 = { 8a 2e [2] ae 20 [2] 85 0c [2] ab 2e [2] bf 35 [2] b0 2f [2] ae 32 [2] ac 33 [2] b7 35 [2] ab 32 [2] b7 1d }

  condition:
    any of them
}