rule TTP_XOR_QUAD_CurrentVersionRun_2001 {
  strings:
    $key_2001 = { 73 6e [2] 57 60 [2] 7c 4c [2] 52 6e [2] 46 75 [2] 49 6f [2] 57 72 [2] 55 73 [2] 4e 75 [2] 52 72 [2] 4e 5d }

  condition:
    any of them
}