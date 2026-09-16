rule TTP_XOR_QUAD_CurrentVersionRun_790e {
  strings:
    $key_790e = { 2a 61 [2] 0e 6f [2] 25 43 [2] 0b 61 [2] 1f 7a [2] 10 60 [2] 0e 7d [2] 0c 7c [2] 17 7a [2] 0b 7d [2] 17 52 }

  condition:
    any of them
}