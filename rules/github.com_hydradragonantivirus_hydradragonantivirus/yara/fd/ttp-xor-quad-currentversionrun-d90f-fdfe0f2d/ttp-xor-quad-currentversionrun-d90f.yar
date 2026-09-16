rule TTP_XOR_QUAD_CurrentVersionRun_d90f {
  strings:
    $key_d90f = { 8a 60 [2] ae 6e [2] 85 42 [2] ab 60 [2] bf 7b [2] b0 61 [2] ae 7c [2] ac 7d [2] b7 7b [2] ab 7c [2] b7 53 }

  condition:
    any of them
}