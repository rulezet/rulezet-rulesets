rule TTP_XOR_QUAD_CurrentVersionRun_3329 {
  strings:
    $key_3329 = { 60 46 [2] 44 48 [2] 6f 64 [2] 41 46 [2] 55 5d [2] 5a 47 [2] 44 5a [2] 46 5b [2] 5d 5d [2] 41 5a [2] 5d 75 }

  condition:
    any of them
}