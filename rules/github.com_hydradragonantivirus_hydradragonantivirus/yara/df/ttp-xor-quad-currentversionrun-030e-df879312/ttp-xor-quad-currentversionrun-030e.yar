rule TTP_XOR_QUAD_CurrentVersionRun_030e {
  strings:
    $key_030e = { 50 61 [2] 74 6f [2] 5f 43 [2] 71 61 [2] 65 7a [2] 6a 60 [2] 74 7d [2] 76 7c [2] 6d 7a [2] 71 7d [2] 6d 52 }

  condition:
    any of them
}