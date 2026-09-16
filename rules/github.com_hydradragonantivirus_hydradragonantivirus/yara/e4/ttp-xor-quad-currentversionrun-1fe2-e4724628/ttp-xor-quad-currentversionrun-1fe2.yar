rule TTP_XOR_QUAD_CurrentVersionRun_1fe2 {
  strings:
    $key_1fe2 = { 4c 8d [2] 68 83 [2] 43 af [2] 6d 8d [2] 79 96 [2] 76 8c [2] 68 91 [2] 6a 90 [2] 71 96 [2] 6d 91 [2] 71 be }

  condition:
    any of them
}