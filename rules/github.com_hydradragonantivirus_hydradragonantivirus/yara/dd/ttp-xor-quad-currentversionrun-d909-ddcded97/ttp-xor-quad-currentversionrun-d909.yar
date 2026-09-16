rule TTP_XOR_QUAD_CurrentVersionRun_d909 {
  strings:
    $key_d909 = { 8a 66 [2] ae 68 [2] 85 44 [2] ab 66 [2] bf 7d [2] b0 67 [2] ae 7a [2] ac 7b [2] b7 7d [2] ab 7a [2] b7 55 }

  condition:
    any of them
}