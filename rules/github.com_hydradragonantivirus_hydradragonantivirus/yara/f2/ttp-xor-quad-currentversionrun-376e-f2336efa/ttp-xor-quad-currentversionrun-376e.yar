rule TTP_XOR_QUAD_CurrentVersionRun_376e {
  strings:
    $key_376e = { 64 01 [2] 40 0f [2] 6b 23 [2] 45 01 [2] 51 1a [2] 5e 00 [2] 40 1d [2] 42 1c [2] 59 1a [2] 45 1d [2] 59 32 }

  condition:
    any of them
}