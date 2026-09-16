rule TTP_XOR_QUAD_CurrentVersionRun_d971 {
  strings:
    $key_d971 = { 8a 1e [2] ae 10 [2] 85 3c [2] ab 1e [2] bf 05 [2] b0 1f [2] ae 02 [2] ac 03 [2] b7 05 [2] ab 02 [2] b7 2d }

  condition:
    any of them
}