rule TTP_XOR_QUAD_CurrentVersionRun_f24f {
  strings:
    $key_f24f = { a1 20 [2] 85 2e [2] ae 02 [2] 80 20 [2] 94 3b [2] 9b 21 [2] 85 3c [2] 87 3d [2] 9c 3b [2] 80 3c [2] 9c 13 }

  condition:
    any of them
}