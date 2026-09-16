rule TTP_XOR_QUAD_CurrentVersionRun_d934 {
  strings:
    $key_d934 = { 8a 5b [2] ae 55 [2] 85 79 [2] ab 5b [2] bf 40 [2] b0 5a [2] ae 47 [2] ac 46 [2] b7 40 [2] ab 47 [2] b7 68 }

  condition:
    any of them
}