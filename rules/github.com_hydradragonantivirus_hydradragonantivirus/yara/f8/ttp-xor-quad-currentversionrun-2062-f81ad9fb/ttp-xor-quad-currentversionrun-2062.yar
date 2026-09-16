rule TTP_XOR_QUAD_CurrentVersionRun_2062 {
  strings:
    $key_2062 = { 73 0d [2] 57 03 [2] 7c 2f [2] 52 0d [2] 46 16 [2] 49 0c [2] 57 11 [2] 55 10 [2] 4e 16 [2] 52 11 [2] 4e 3e }

  condition:
    any of them
}