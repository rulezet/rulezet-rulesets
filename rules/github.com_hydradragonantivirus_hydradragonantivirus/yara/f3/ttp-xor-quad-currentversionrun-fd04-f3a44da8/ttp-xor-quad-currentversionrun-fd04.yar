rule TTP_XOR_QUAD_CurrentVersionRun_fd04 {
  strings:
    $key_fd04 = { ae 6b [2] 8a 65 [2] a1 49 [2] 8f 6b [2] 9b 70 [2] 94 6a [2] 8a 77 [2] 88 76 [2] 93 70 [2] 8f 77 [2] 93 58 }

  condition:
    any of them
}