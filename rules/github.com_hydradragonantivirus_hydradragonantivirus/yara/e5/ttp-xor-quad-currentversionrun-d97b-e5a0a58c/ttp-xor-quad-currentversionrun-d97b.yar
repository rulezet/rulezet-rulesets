rule TTP_XOR_QUAD_CurrentVersionRun_d97b {
  strings:
    $key_d97b = { 8a 14 [2] ae 1a [2] 85 36 [2] ab 14 [2] bf 0f [2] b0 15 [2] ae 08 [2] ac 09 [2] b7 0f [2] ab 08 [2] b7 27 }

  condition:
    any of them
}