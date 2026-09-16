rule TTP_XOR_QUAD_CurrentVersionRun_4ce2 {
  strings:
    $key_4ce2 = { 1f 8d [2] 3b 83 [2] 10 af [2] 3e 8d [2] 2a 96 [2] 25 8c [2] 3b 91 [2] 39 90 [2] 22 96 [2] 3e 91 [2] 22 be }

  condition:
    any of them
}