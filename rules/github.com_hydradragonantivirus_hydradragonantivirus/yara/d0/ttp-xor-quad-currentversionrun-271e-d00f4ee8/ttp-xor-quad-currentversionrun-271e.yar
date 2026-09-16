rule TTP_XOR_QUAD_CurrentVersionRun_271e {
  strings:
    $key_271e = { 74 71 [2] 50 7f [2] 7b 53 [2] 55 71 [2] 41 6a [2] 4e 70 [2] 50 6d [2] 52 6c [2] 49 6a [2] 55 6d [2] 49 42 }

  condition:
    any of them
}