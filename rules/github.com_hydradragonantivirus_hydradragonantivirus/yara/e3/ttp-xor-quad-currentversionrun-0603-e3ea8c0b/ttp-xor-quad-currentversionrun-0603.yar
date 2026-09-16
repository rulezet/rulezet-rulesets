rule TTP_XOR_QUAD_CurrentVersionRun_0603 {
  strings:
    $key_0603 = { 55 6c [2] 71 62 [2] 5a 4e [2] 74 6c [2] 60 77 [2] 6f 6d [2] 71 70 [2] 73 71 [2] 68 77 [2] 74 70 [2] 68 5f }

  condition:
    any of them
}