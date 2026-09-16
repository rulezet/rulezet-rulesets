rule TTP_XOR_QUAD_CurrentVersionRun_026e {
  strings:
    $key_026e = { 51 01 [2] 75 0f [2] 5e 23 [2] 70 01 [2] 64 1a [2] 6b 00 [2] 75 1d [2] 77 1c [2] 6c 1a [2] 70 1d [2] 6c 32 }

  condition:
    any of them
}