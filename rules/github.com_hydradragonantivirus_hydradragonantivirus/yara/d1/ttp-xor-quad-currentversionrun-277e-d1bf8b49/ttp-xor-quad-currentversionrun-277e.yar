rule TTP_XOR_QUAD_CurrentVersionRun_277e {
  strings:
    $key_277e = { 74 11 [2] 50 1f [2] 7b 33 [2] 55 11 [2] 41 0a [2] 4e 10 [2] 50 0d [2] 52 0c [2] 49 0a [2] 55 0d [2] 49 22 }

  condition:
    any of them
}