rule TTP_XOR_QUAD_CurrentVersionRun_471e {
  strings:
    $key_471e = { 14 71 [2] 30 7f [2] 1b 53 [2] 35 71 [2] 21 6a [2] 2e 70 [2] 30 6d [2] 32 6c [2] 29 6a [2] 35 6d [2] 29 42 }

  condition:
    any of them
}