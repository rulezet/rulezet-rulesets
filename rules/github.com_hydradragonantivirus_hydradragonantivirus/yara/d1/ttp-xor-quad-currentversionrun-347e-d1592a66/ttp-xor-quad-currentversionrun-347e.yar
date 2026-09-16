rule TTP_XOR_QUAD_CurrentVersionRun_347e {
  strings:
    $key_347e = { 67 11 [2] 43 1f [2] 68 33 [2] 46 11 [2] 52 0a [2] 5d 10 [2] 43 0d [2] 41 0c [2] 5a 0a [2] 46 0d [2] 5a 22 }

  condition:
    any of them
}