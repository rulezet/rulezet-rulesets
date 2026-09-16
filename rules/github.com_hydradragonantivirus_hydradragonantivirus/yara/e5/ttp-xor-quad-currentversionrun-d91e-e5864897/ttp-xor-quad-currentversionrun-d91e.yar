rule TTP_XOR_QUAD_CurrentVersionRun_d91e {
  strings:
    $key_d91e = { 8a 71 [2] ae 7f [2] 85 53 [2] ab 71 [2] bf 6a [2] b0 70 [2] ae 6d [2] ac 6c [2] b7 6a [2] ab 6d [2] b7 42 }

  condition:
    any of them
}