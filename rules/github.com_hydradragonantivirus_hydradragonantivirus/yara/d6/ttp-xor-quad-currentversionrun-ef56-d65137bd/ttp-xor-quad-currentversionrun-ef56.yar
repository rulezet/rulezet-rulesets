rule TTP_XOR_QUAD_CurrentVersionRun_ef56 {
  strings:
    $key_ef56 = { bc 39 [2] 98 37 [2] b3 1b [2] 9d 39 [2] 89 22 [2] 86 38 [2] 98 25 [2] 9a 24 [2] 81 22 [2] 9d 25 [2] 81 0a }

  condition:
    any of them
}