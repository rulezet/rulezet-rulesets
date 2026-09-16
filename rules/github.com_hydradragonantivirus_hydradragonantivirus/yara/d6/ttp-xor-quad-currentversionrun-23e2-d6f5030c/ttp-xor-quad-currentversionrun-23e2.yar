rule TTP_XOR_QUAD_CurrentVersionRun_23e2 {
  strings:
    $key_23e2 = { 70 8d [2] 54 83 [2] 7f af [2] 51 8d [2] 45 96 [2] 4a 8c [2] 54 91 [2] 56 90 [2] 4d 96 [2] 51 91 [2] 4d be }

  condition:
    any of them
}