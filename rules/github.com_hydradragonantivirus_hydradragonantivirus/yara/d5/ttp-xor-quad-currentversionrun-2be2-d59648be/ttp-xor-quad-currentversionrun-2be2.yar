rule TTP_XOR_QUAD_CurrentVersionRun_2be2 {
  strings:
    $key_2be2 = { 78 8d [2] 5c 83 [2] 77 af [2] 59 8d [2] 4d 96 [2] 42 8c [2] 5c 91 [2] 5e 90 [2] 45 96 [2] 59 91 [2] 45 be }

  condition:
    any of them
}