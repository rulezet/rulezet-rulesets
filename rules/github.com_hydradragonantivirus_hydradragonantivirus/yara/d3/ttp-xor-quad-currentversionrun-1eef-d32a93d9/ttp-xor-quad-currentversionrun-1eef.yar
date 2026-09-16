rule TTP_XOR_QUAD_CurrentVersionRun_1eef {
  strings:
    $key_1eef = { 4d 80 [2] 69 8e [2] 42 a2 [2] 6c 80 [2] 78 9b [2] 77 81 [2] 69 9c [2] 6b 9d [2] 70 9b [2] 6c 9c [2] 70 b3 }

  condition:
    any of them
}