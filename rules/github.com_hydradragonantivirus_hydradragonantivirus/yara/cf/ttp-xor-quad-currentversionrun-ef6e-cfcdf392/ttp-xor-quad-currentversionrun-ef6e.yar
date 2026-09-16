rule TTP_XOR_QUAD_CurrentVersionRun_ef6e {
  strings:
    $key_ef6e = { bc 01 [2] 98 0f [2] b3 23 [2] 9d 01 [2] 89 1a [2] 86 00 [2] 98 1d [2] 9a 1c [2] 81 1a [2] 9d 1d [2] 81 32 }

  condition:
    any of them
}