rule TTP_XOR_QUAD_CurrentVersionRun_276e {
  strings:
    $key_276e = { 74 01 [2] 50 0f [2] 7b 23 [2] 55 01 [2] 41 1a [2] 4e 00 [2] 50 1d [2] 52 1c [2] 49 1a [2] 55 1d [2] 49 32 }

  condition:
    any of them
}