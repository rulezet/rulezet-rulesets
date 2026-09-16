rule TTP_XOR_QUAD_CurrentVersionRun_306e {
  strings:
    $key_306e = { 63 01 [2] 47 0f [2] 6c 23 [2] 42 01 [2] 56 1a [2] 59 00 [2] 47 1d [2] 45 1c [2] 5e 1a [2] 42 1d [2] 5e 32 }

  condition:
    any of them
}