rule TTP_XOR_QUAD_CurrentVersionRun_d91d {
  strings:
    $key_d91d = { 8a 72 [2] ae 7c [2] 85 50 [2] ab 72 [2] bf 69 [2] b0 73 [2] ae 6e [2] ac 6f [2] b7 69 [2] ab 6e [2] b7 41 }

  condition:
    any of them
}