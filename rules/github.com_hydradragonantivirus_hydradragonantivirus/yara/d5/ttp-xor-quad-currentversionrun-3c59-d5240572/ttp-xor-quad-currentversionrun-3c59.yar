rule TTP_XOR_QUAD_CurrentVersionRun_3c59 {
  strings:
    $key_3c59 = { 6f 36 [2] 4b 38 [2] 60 14 [2] 4e 36 [2] 5a 2d [2] 55 37 [2] 4b 2a [2] 49 2b [2] 52 2d [2] 4e 2a [2] 52 05 }

  condition:
    any of them
}