rule TTP_XOR_QUAD_CurrentVersionRun_e81e {
  strings:
    $key_e81e = { bb 71 [2] 9f 7f [2] b4 53 [2] 9a 71 [2] 8e 6a [2] 81 70 [2] 9f 6d [2] 9d 6c [2] 86 6a [2] 9a 6d [2] 86 42 }

  condition:
    any of them
}