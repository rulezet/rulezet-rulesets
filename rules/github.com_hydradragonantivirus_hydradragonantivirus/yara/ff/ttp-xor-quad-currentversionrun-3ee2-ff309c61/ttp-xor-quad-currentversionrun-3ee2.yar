rule TTP_XOR_QUAD_CurrentVersionRun_3ee2 {
  strings:
    $key_3ee2 = { 6d 8d [2] 49 83 [2] 62 af [2] 4c 8d [2] 58 96 [2] 57 8c [2] 49 91 [2] 4b 90 [2] 50 96 [2] 4c 91 [2] 50 be }

  condition:
    any of them
}