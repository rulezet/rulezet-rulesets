rule TTP_XOR_QUAD_CurrentVersionRun_d921 {
  strings:
    $key_d921 = { 8a 4e [2] ae 40 [2] 85 6c [2] ab 4e [2] bf 55 [2] b0 4f [2] ae 52 [2] ac 53 [2] b7 55 [2] ab 52 [2] b7 7d }

  condition:
    any of them
}