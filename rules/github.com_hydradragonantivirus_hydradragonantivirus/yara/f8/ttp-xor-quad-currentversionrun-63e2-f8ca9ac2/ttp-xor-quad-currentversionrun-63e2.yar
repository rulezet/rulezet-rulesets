rule TTP_XOR_QUAD_CurrentVersionRun_63e2 {
  strings:
    $key_63e2 = { 30 8d [2] 14 83 [2] 3f af [2] 11 8d [2] 05 96 [2] 0a 8c [2] 14 91 [2] 16 90 [2] 0d 96 [2] 11 91 [2] 0d be }

  condition:
    any of them
}