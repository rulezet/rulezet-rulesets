rule TTP_XOR_QUAD_CurrentVersionRun_096e {
  strings:
    $key_096e = { 5a 01 [2] 7e 0f [2] 55 23 [2] 7b 01 [2] 6f 1a [2] 60 00 [2] 7e 1d [2] 7c 1c [2] 67 1a [2] 7b 1d [2] 67 32 }

  condition:
    any of them
}