rule TTP_XOR_QUAD_CurrentVersionRun_17e2 {
  strings:
    $key_17e2 = { 44 8d [2] 60 83 [2] 4b af [2] 65 8d [2] 71 96 [2] 7e 8c [2] 60 91 [2] 62 90 [2] 79 96 [2] 65 91 [2] 79 be }

  condition:
    any of them
}