rule TTP_XOR_QUAD_CurrentVersionRun_d93f {
  strings:
    $key_d93f = { 8a 50 [2] ae 5e [2] 85 72 [2] ab 50 [2] bf 4b [2] b0 51 [2] ae 4c [2] ac 4d [2] b7 4b [2] ab 4c [2] b7 63 }

  condition:
    any of them
}