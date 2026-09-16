rule TTP_XOR_QUAD_CurrentVersionRun_06e2 {
  strings:
    $key_06e2 = { 55 8d [2] 71 83 [2] 5a af [2] 74 8d [2] 60 96 [2] 6f 8c [2] 71 91 [2] 73 90 [2] 68 96 [2] 74 91 [2] 68 be }

  condition:
    any of them
}