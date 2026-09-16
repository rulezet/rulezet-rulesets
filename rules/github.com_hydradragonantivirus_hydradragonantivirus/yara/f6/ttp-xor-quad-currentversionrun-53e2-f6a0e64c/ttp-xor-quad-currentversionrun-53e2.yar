rule TTP_XOR_QUAD_CurrentVersionRun_53e2 {
  strings:
    $key_53e2 = { 00 8d [2] 24 83 [2] 0f af [2] 21 8d [2] 35 96 [2] 3a 8c [2] 24 91 [2] 26 90 [2] 3d 96 [2] 21 91 [2] 3d be }

  condition:
    any of them
}