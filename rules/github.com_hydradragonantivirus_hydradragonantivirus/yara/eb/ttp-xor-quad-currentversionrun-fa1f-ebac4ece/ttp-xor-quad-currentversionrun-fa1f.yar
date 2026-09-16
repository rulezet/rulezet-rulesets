rule TTP_XOR_QUAD_CurrentVersionRun_fa1f {
  strings:
    $key_fa1f = { a9 70 [2] 8d 7e [2] a6 52 [2] 88 70 [2] 9c 6b [2] 93 71 [2] 8d 6c [2] 8f 6d [2] 94 6b [2] 88 6c [2] 94 43 }

  condition:
    any of them
}