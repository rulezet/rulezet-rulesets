rule TTP_XOR_QUAD_CurrentVersionRun_39e2 {
  strings:
    $key_39e2 = { 6a 8d [2] 4e 83 [2] 65 af [2] 4b 8d [2] 5f 96 [2] 50 8c [2] 4e 91 [2] 4c 90 [2] 57 96 [2] 4b 91 [2] 57 be }

  condition:
    any of them
}