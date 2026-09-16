rule TTP_XOR_QUAD_CurrentVersionRun_d92d {
  strings:
    $key_d92d = { 8a 42 [2] ae 4c [2] 85 60 [2] ab 42 [2] bf 59 [2] b0 43 [2] ae 5e [2] ac 5f [2] b7 59 [2] ab 5e [2] b7 71 }

  condition:
    any of them
}