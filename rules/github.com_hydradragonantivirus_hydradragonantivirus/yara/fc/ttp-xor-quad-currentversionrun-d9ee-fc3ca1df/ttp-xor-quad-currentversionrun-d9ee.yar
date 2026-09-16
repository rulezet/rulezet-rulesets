rule TTP_XOR_QUAD_CurrentVersionRun_d9ee {
  strings:
    $key_d9ee = { 8a 81 [2] ae 8f [2] 85 a3 [2] ab 81 [2] bf 9a [2] b0 80 [2] ae 9d [2] ac 9c [2] b7 9a [2] ab 9d [2] b7 b2 }

  condition:
    any of them
}