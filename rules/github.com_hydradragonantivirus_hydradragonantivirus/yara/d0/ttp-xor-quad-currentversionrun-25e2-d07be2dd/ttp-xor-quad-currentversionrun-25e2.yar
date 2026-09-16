rule TTP_XOR_QUAD_CurrentVersionRun_25e2 {
  strings:
    $key_25e2 = { 76 8d [2] 52 83 [2] 79 af [2] 57 8d [2] 43 96 [2] 4c 8c [2] 52 91 [2] 50 90 [2] 4b 96 [2] 57 91 [2] 4b be }

  condition:
    any of them
}