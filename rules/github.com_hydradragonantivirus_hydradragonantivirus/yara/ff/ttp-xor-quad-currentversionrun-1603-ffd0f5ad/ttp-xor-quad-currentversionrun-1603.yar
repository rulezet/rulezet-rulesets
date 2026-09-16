rule TTP_XOR_QUAD_CurrentVersionRun_1603 {
  strings:
    $key_1603 = { 45 6c [2] 61 62 [2] 4a 4e [2] 64 6c [2] 70 77 [2] 7f 6d [2] 61 70 [2] 63 71 [2] 78 77 [2] 64 70 [2] 78 5f }

  condition:
    any of them
}