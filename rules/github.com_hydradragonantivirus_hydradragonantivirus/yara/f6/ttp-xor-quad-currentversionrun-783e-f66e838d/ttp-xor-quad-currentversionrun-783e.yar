rule TTP_XOR_QUAD_CurrentVersionRun_783e {
  strings:
    $key_783e = { 2b 51 [2] 0f 5f [2] 24 73 [2] 0a 51 [2] 1e 4a [2] 11 50 [2] 0f 4d [2] 0d 4c [2] 16 4a [2] 0a 4d [2] 16 62 }

  condition:
    any of them
}