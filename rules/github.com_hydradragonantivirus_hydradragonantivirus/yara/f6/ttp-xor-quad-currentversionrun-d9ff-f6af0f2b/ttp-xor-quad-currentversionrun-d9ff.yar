rule TTP_XOR_QUAD_CurrentVersionRun_d9ff {
  strings:
    $key_d9ff = { 8a 90 [2] ae 9e [2] 85 b2 [2] ab 90 [2] bf 8b [2] b0 91 [2] ae 8c [2] ac 8d [2] b7 8b [2] ab 8c [2] b7 a3 }

  condition:
    any of them
}