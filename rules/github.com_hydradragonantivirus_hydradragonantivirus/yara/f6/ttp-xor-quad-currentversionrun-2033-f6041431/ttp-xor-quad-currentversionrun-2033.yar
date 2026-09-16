rule TTP_XOR_QUAD_CurrentVersionRun_2033 {
  strings:
    $key_2033 = { 73 5c [2] 57 52 [2] 7c 7e [2] 52 5c [2] 46 47 [2] 49 5d [2] 57 40 [2] 55 41 [2] 4e 47 [2] 52 40 [2] 4e 6f }

  condition:
    any of them
}