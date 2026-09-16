rule TTP_XOR_QUAD_CurrentVersionRun_177e {
  strings:
    $key_177e = { 44 11 [2] 60 1f [2] 4b 33 [2] 65 11 [2] 71 0a [2] 7e 10 [2] 60 0d [2] 62 0c [2] 79 0a [2] 65 0d [2] 79 22 }

  condition:
    any of them
}