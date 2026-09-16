rule TTP_XOR_QUAD_CurrentVersionRun_d939 {
  strings:
    $key_d939 = { 8a 56 [2] ae 58 [2] 85 74 [2] ab 56 [2] bf 4d [2] b0 57 [2] ae 4a [2] ac 4b [2] b7 4d [2] ab 4a [2] b7 65 }

  condition:
    any of them
}