rule TTP_XOR_QUAD_CurrentVersionRun_4e3e {
  strings:
    $key_4e3e = { 1d 51 [2] 39 5f [2] 12 73 [2] 3c 51 [2] 28 4a [2] 27 50 [2] 39 4d [2] 3b 4c [2] 20 4a [2] 3c 4d [2] 20 62 }

  condition:
    any of them
}