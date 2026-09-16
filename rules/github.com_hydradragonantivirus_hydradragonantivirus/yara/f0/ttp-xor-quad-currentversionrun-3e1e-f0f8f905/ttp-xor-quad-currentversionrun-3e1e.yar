rule TTP_XOR_QUAD_CurrentVersionRun_3e1e {
  strings:
    $key_3e1e = { 6d 71 [2] 49 7f [2] 62 53 [2] 4c 71 [2] 58 6a [2] 57 70 [2] 49 6d [2] 4b 6c [2] 50 6a [2] 4c 6d [2] 50 42 }

  condition:
    any of them
}