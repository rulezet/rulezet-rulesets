rule TTP_XOR_QUAD_CurrentVersionRun_3be2 {
  strings:
    $key_3be2 = { 68 8d [2] 4c 83 [2] 67 af [2] 49 8d [2] 5d 96 [2] 52 8c [2] 4c 91 [2] 4e 90 [2] 55 96 [2] 49 91 [2] 55 be }

  condition:
    any of them
}