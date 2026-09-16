rule TTP_XOR_QUAD_CurrentVersionRun_361e {
  strings:
    $key_361e = { 65 71 [2] 41 7f [2] 6a 53 [2] 44 71 [2] 50 6a [2] 5f 70 [2] 41 6d [2] 43 6c [2] 58 6a [2] 44 6d [2] 58 42 }

  condition:
    any of them
}