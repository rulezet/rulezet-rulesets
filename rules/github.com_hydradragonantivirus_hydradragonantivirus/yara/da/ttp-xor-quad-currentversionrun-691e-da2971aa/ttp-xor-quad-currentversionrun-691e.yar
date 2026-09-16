rule TTP_XOR_QUAD_CurrentVersionRun_691e {
  strings:
    $key_691e = { 3a 71 [2] 1e 7f [2] 35 53 [2] 1b 71 [2] 0f 6a [2] 00 70 [2] 1e 6d [2] 1c 6c [2] 07 6a [2] 1b 6d [2] 07 42 }

  condition:
    any of them
}