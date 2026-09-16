rule TTP_XOR_QUAD_CurrentVersionRun_0f7e {
  strings:
    $key_0f7e = { 5c 11 [2] 78 1f [2] 53 33 [2] 7d 11 [2] 69 0a [2] 66 10 [2] 78 0d [2] 7a 0c [2] 61 0a [2] 7d 0d [2] 61 22 }

  condition:
    any of them
}