rule TTP_XOR_QUAD_CurrentVersionRun_d920 {
  strings:
    $key_d920 = { 8a 4f [2] ae 41 [2] 85 6d [2] ab 4f [2] bf 54 [2] b0 4e [2] ae 53 [2] ac 52 [2] b7 54 [2] ab 53 [2] b7 7c }

  condition:
    any of them
}