rule TTP_XOR_QUAD_CurrentVersionRun_2000 {
  strings:
    $key_2000 = { 73 6f [2] 57 61 [2] 7c 4d [2] 52 6f [2] 46 74 [2] 49 6e [2] 57 73 [2] 55 72 [2] 4e 74 [2] 52 73 [2] 4e 5c }

  condition:
    any of them
}