rule TTP_XOR_QUAD_CurrentVersionRun_246e {
  strings:
    $key_246e = { 77 01 [2] 53 0f [2] 78 23 [2] 56 01 [2] 42 1a [2] 4d 00 [2] 53 1d [2] 51 1c [2] 4a 1a [2] 56 1d [2] 4a 32 }

  condition:
    any of them
}