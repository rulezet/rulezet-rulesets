rule TTP_XOR_QUAD_CurrentVersionRun_106e {
  strings:
    $key_106e = { 43 01 [2] 67 0f [2] 4c 23 [2] 62 01 [2] 76 1a [2] 79 00 [2] 67 1d [2] 65 1c [2] 7e 1a [2] 62 1d [2] 7e 32 }

  condition:
    any of them
}