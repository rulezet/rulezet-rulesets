rule TTP_XOR_QUAD_CurrentVersionRun_d90e {
  strings:
    $key_d90e = { 8a 61 [2] ae 6f [2] 85 43 [2] ab 61 [2] bf 7a [2] b0 60 [2] ae 7d [2] ac 7c [2] b7 7a [2] ab 7d [2] b7 52 }

  condition:
    any of them
}