rule TTP_XOR_QUAD_CurrentVersionRun_d918 {
  strings:
    $key_d918 = { 8a 77 [2] ae 79 [2] 85 55 [2] ab 77 [2] bf 6c [2] b0 76 [2] ae 6b [2] ac 6a [2] b7 6c [2] ab 6b [2] b7 44 }

  condition:
    any of them
}