rule TTP_XOR_QUAD_CurrentVersionRun_101e {
  strings:
    $key_101e = { 43 71 [2] 67 7f [2] 4c 53 [2] 62 71 [2] 76 6a [2] 79 70 [2] 67 6d [2] 65 6c [2] 7e 6a [2] 62 6d [2] 7e 42 }

  condition:
    any of them
}