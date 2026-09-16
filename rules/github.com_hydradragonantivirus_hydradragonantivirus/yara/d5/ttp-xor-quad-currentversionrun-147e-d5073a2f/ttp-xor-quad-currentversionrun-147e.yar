rule TTP_XOR_QUAD_CurrentVersionRun_147e {
  strings:
    $key_147e = { 47 11 [2] 63 1f [2] 48 33 [2] 66 11 [2] 72 0a [2] 7d 10 [2] 63 0d [2] 61 0c [2] 7a 0a [2] 66 0d [2] 7a 22 }

  condition:
    any of them
}