rule TTP_XOR_QUAD_CurrentVersionRun_d95c {
  strings:
    $key_d95c = { 8a 33 [2] ae 3d [2] 85 11 [2] ab 33 [2] bf 28 [2] b0 32 [2] ae 2f [2] ac 2e [2] b7 28 [2] ab 2f [2] b7 00 }

  condition:
    any of them
}