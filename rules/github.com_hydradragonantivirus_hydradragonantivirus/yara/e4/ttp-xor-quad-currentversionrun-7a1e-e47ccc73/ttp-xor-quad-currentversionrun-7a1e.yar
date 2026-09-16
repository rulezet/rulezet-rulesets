rule TTP_XOR_QUAD_CurrentVersionRun_7a1e {
  strings:
    $key_7a1e = { 29 71 [2] 0d 7f [2] 26 53 [2] 08 71 [2] 1c 6a [2] 13 70 [2] 0d 6d [2] 0f 6c [2] 14 6a [2] 08 6d [2] 14 42 }

  condition:
    any of them
}