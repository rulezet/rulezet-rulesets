rule TTP_XOR_QUAD_CurrentVersionRun_f3e2 {
  strings:
    $key_f3e2 = { a0 8d [2] 84 83 [2] af af [2] 81 8d [2] 95 96 [2] 9a 8c [2] 84 91 [2] 86 90 [2] 9d 96 [2] 81 91 [2] 9d be }

  condition:
    any of them
}