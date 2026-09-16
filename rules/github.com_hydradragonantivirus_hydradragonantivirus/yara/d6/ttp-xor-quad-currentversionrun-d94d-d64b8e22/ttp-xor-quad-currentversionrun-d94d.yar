rule TTP_XOR_QUAD_CurrentVersionRun_d94d {
  strings:
    $key_d94d = { 8a 22 [2] ae 2c [2] 85 00 [2] ab 22 [2] bf 39 [2] b0 23 [2] ae 3e [2] ac 3f [2] b7 39 [2] ab 3e [2] b7 11 }

  condition:
    any of them
}