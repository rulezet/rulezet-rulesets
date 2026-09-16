rule TTP_XOR_QUAD_CurrentVersionRun_337e {
  strings:
    $key_337e = { 60 11 [2] 44 1f [2] 6f 33 [2] 41 11 [2] 55 0a [2] 5a 10 [2] 44 0d [2] 46 0c [2] 5d 0a [2] 41 0d [2] 5d 22 }

  condition:
    any of them
}