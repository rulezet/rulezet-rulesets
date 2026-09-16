rule TTP_XOR_QUAD_CurrentVersionRun_d942 {
  strings:
    $key_d942 = { 8a 2d [2] ae 23 [2] 85 0f [2] ab 2d [2] bf 36 [2] b0 2c [2] ae 31 [2] ac 30 [2] b7 36 [2] ab 31 [2] b7 1e }

  condition:
    any of them
}