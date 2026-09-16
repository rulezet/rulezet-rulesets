rule TTP_XOR_QUAD_CurrentVersionRun_fd6b {
  strings:
    $key_fd6b = { ae 04 [2] 8a 0a [2] a1 26 [2] 8f 04 [2] 9b 1f [2] 94 05 [2] 8a 18 [2] 88 19 [2] 93 1f [2] 8f 18 [2] 93 37 }

  condition:
    any of them
}