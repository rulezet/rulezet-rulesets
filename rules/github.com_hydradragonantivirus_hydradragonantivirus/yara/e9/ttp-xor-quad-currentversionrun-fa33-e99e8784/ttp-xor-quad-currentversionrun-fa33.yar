rule TTP_XOR_QUAD_CurrentVersionRun_fa33 {
  strings:
    $key_fa33 = { a9 5c [2] 8d 52 [2] a6 7e [2] 88 5c [2] 9c 47 [2] 93 5d [2] 8d 40 [2] 8f 41 [2] 94 47 [2] 88 40 [2] 94 6f }

  condition:
    any of them
}