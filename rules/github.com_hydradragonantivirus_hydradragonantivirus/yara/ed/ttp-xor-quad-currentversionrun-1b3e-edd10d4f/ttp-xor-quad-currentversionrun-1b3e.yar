rule TTP_XOR_QUAD_CurrentVersionRun_1b3e {
  strings:
    $key_1b3e = { 48 51 [2] 6c 5f [2] 47 73 [2] 69 51 [2] 7d 4a [2] 72 50 [2] 6c 4d [2] 6e 4c [2] 75 4a [2] 69 4d [2] 75 62 }

  condition:
    any of them
}