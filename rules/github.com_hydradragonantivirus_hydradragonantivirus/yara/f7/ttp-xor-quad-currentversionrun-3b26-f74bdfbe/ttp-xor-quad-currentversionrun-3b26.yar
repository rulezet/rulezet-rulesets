rule TTP_XOR_QUAD_CurrentVersionRun_3b26 {
  strings:
    $key_3b26 = { 68 49 [2] 4c 47 [2] 67 6b [2] 49 49 [2] 5d 52 [2] 52 48 [2] 4c 55 [2] 4e 54 [2] 55 52 [2] 49 55 [2] 55 7a }

  condition:
    any of them
}