rule TTP_XOR_QUAD_CurrentVersionRun_d91f {
  strings:
    $key_d91f = { 8a 70 [2] ae 7e [2] 85 52 [2] ab 70 [2] bf 6b [2] b0 71 [2] ae 6c [2] ac 6d [2] b7 6b [2] ab 6c [2] b7 43 }

  condition:
    any of them
}