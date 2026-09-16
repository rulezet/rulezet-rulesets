rule TTP_XOR_QUAD_CurrentVersionRun_312f {
  strings:
    $key_312f = { 62 40 [2] 46 4e [2] 6d 62 [2] 43 40 [2] 57 5b [2] 58 41 [2] 46 5c [2] 44 5d [2] 5f 5b [2] 43 5c [2] 5f 73 }

  condition:
    any of them
}