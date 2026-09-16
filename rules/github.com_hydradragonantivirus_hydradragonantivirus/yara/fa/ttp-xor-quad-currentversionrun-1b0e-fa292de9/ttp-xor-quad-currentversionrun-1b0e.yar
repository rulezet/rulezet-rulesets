rule TTP_XOR_QUAD_CurrentVersionRun_1b0e {
  strings:
    $key_1b0e = { 48 61 [2] 6c 6f [2] 47 43 [2] 69 61 [2] 7d 7a [2] 72 60 [2] 6c 7d [2] 6e 7c [2] 75 7a [2] 69 7d [2] 75 52 }

  condition:
    any of them
}