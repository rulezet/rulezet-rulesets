rule TTP_XOR_QUAD_CurrentVersionRun_690e {
  strings:
    $key_690e = { 3a 61 [2] 1e 6f [2] 35 43 [2] 1b 61 [2] 0f 7a [2] 00 60 [2] 1e 7d [2] 1c 7c [2] 07 7a [2] 1b 7d [2] 07 52 }

  condition:
    any of them
}