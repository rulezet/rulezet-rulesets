rule TTP_XOR_QUAD_CurrentVersionRun_faff {
  strings:
    $key_faff = { a9 90 [2] 8d 9e [2] a6 b2 [2] 88 90 [2] 9c 8b [2] 93 91 [2] 8d 8c [2] 8f 8d [2] 94 8b [2] 88 8c [2] 94 a3 }

  condition:
    any of them
}