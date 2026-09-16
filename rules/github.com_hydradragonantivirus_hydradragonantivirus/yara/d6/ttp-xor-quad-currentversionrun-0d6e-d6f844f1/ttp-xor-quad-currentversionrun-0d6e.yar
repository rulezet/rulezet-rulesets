rule TTP_XOR_QUAD_CurrentVersionRun_0d6e {
  strings:
    $key_0d6e = { 5e 01 [2] 7a 0f [2] 51 23 [2] 7f 01 [2] 6b 1a [2] 64 00 [2] 7a 1d [2] 78 1c [2] 63 1a [2] 7f 1d [2] 63 32 }

  condition:
    any of them
}