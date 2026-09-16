rule TTP_XOR_QUAD_CurrentVersionRun_e32f {
  strings:
    $key_e32f = { b0 40 [2] 94 4e [2] bf 62 [2] 91 40 [2] 85 5b [2] 8a 41 [2] 94 5c [2] 96 5d [2] 8d 5b [2] 91 5c [2] 8d 73 }

  condition:
    any of them
}