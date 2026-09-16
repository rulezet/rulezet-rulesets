rule TTP_XOR_QUAD_CurrentVersionRun_fa03 {
  strings:
    $key_fa03 = { a9 6c [2] 8d 62 [2] a6 4e [2] 88 6c [2] 9c 77 [2] 93 6d [2] 8d 70 [2] 8f 71 [2] 94 77 [2] 88 70 [2] 94 5f }

  condition:
    any of them
}