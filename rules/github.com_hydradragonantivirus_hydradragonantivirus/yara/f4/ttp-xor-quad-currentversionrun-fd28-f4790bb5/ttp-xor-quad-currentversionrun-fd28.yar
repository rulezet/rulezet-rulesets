rule TTP_XOR_QUAD_CurrentVersionRun_fd28 {
  strings:
    $key_fd28 = { ae 47 [2] 8a 49 [2] a1 65 [2] 8f 47 [2] 9b 5c [2] 94 46 [2] 8a 5b [2] 88 5a [2] 93 5c [2] 8f 5b [2] 93 74 }

  condition:
    any of them
}