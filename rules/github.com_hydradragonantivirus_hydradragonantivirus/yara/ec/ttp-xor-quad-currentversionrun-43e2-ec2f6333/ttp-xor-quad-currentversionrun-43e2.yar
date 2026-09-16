rule TTP_XOR_QUAD_CurrentVersionRun_43e2 {
  strings:
    $key_43e2 = { 10 8d [2] 34 83 [2] 1f af [2] 31 8d [2] 25 96 [2] 2a 8c [2] 34 91 [2] 36 90 [2] 2d 96 [2] 31 91 [2] 2d be }

  condition:
    any of them
}