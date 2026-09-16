rule TTP_XOR_QUAD_CurrentVersionRun_ef03 {
  strings:
    $key_ef03 = { bc 6c [2] 98 62 [2] b3 4e [2] 9d 6c [2] 89 77 [2] 86 6d [2] 98 70 [2] 9a 71 [2] 81 77 [2] 9d 70 [2] 81 5f }

  condition:
    any of them
}