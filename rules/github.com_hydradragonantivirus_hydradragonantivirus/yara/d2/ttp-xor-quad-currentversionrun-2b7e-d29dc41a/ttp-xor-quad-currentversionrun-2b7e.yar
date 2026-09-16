rule TTP_XOR_QUAD_CurrentVersionRun_2b7e {
  strings:
    $key_2b7e = { 78 11 [2] 5c 1f [2] 77 33 [2] 59 11 [2] 4d 0a [2] 42 10 [2] 5c 0d [2] 5e 0c [2] 45 0a [2] 59 0d [2] 45 22 }

  condition:
    any of them
}