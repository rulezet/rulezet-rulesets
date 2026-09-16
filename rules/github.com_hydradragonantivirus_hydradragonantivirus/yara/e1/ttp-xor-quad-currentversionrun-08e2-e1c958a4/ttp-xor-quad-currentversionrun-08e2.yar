rule TTP_XOR_QUAD_CurrentVersionRun_08e2 {
  strings:
    $key_08e2 = { 5b 8d [2] 7f 83 [2] 54 af [2] 7a 8d [2] 6e 96 [2] 61 8c [2] 7f 91 [2] 7d 90 [2] 66 96 [2] 7a 91 [2] 66 be }

  condition:
    any of them
}