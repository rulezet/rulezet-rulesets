rule TTP_XOR_QUAD_CurrentVersionRun_0e1e {
  strings:
    $key_0e1e = { 5d 71 [2] 79 7f [2] 52 53 [2] 7c 71 [2] 68 6a [2] 67 70 [2] 79 6d [2] 7b 6c [2] 60 6a [2] 7c 6d [2] 60 42 }

  condition:
    any of them
}