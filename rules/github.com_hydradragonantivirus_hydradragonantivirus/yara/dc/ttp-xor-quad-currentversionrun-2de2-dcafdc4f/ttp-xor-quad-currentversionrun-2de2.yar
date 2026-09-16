rule TTP_XOR_QUAD_CurrentVersionRun_2de2 {
  strings:
    $key_2de2 = { 7e 8d [2] 5a 83 [2] 71 af [2] 5f 8d [2] 4b 96 [2] 44 8c [2] 5a 91 [2] 58 90 [2] 43 96 [2] 5f 91 [2] 43 be }

  condition:
    any of them
}