rule TTP_XOR_QUAD_CurrentVersionRun_311e {
  strings:
    $key_311e = { 62 71 [2] 46 7f [2] 6d 53 [2] 43 71 [2] 57 6a [2] 58 70 [2] 46 6d [2] 44 6c [2] 5f 6a [2] 43 6d [2] 5f 42 }

  condition:
    any of them
}