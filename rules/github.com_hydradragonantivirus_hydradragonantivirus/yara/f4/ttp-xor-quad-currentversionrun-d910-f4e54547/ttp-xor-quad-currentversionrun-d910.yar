rule TTP_XOR_QUAD_CurrentVersionRun_d910 {
  strings:
    $key_d910 = { 8a 7f [2] ae 71 [2] 85 5d [2] ab 7f [2] bf 64 [2] b0 7e [2] ae 63 [2] ac 62 [2] b7 64 [2] ab 63 [2] b7 4c }

  condition:
    any of them
}