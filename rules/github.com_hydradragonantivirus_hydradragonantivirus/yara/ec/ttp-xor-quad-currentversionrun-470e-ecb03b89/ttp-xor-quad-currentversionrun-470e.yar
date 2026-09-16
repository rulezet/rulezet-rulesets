rule TTP_XOR_QUAD_CurrentVersionRun_470e {
  strings:
    $key_470e = { 14 61 [2] 30 6f [2] 1b 43 [2] 35 61 [2] 21 7a [2] 2e 60 [2] 30 7d [2] 32 7c [2] 29 7a [2] 35 7d [2] 29 52 }

  condition:
    any of them
}