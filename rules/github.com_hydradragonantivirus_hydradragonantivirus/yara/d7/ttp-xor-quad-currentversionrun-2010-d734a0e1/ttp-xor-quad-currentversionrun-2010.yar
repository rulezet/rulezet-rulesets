rule TTP_XOR_QUAD_CurrentVersionRun_2010 {
  strings:
    $key_2010 = { 73 7f [2] 57 71 [2] 7c 5d [2] 52 7f [2] 46 64 [2] 49 7e [2] 57 63 [2] 55 62 [2] 4e 64 [2] 52 63 [2] 4e 4c }

  condition:
    any of them
}