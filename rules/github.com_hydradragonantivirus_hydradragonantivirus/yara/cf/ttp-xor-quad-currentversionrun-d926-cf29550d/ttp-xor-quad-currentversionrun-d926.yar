rule TTP_XOR_QUAD_CurrentVersionRun_d926 {
  strings:
    $key_d926 = { 8a 49 [2] ae 47 [2] 85 6b [2] ab 49 [2] bf 52 [2] b0 48 [2] ae 55 [2] ac 54 [2] b7 52 [2] ab 55 [2] b7 7a }

  condition:
    any of them
}