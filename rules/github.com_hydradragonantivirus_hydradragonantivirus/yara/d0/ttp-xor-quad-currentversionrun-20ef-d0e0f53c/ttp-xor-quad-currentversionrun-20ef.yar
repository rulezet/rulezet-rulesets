rule TTP_XOR_QUAD_CurrentVersionRun_20ef {
  strings:
    $key_20ef = { 73 80 [2] 57 8e [2] 7c a2 [2] 52 80 [2] 46 9b [2] 49 81 [2] 57 9c [2] 55 9d [2] 4e 9b [2] 52 9c [2] 4e b3 }

  condition:
    any of them
}