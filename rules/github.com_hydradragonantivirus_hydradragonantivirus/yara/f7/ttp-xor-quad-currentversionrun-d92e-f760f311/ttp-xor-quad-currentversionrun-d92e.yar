rule TTP_XOR_QUAD_CurrentVersionRun_d92e {
  strings:
    $key_d92e = { 8a 41 [2] ae 4f [2] 85 63 [2] ab 41 [2] bf 5a [2] b0 40 [2] ae 5d [2] ac 5c [2] b7 5a [2] ab 5d [2] b7 72 }

  condition:
    any of them
}