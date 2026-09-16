rule TTP_XOR_QUAD_CurrentVersionRun_fae9 {
  strings:
    $key_fae9 = { a9 86 [2] 8d 88 [2] a6 a4 [2] 88 86 [2] 9c 9d [2] 93 87 [2] 8d 9a [2] 8f 9b [2] 94 9d [2] 88 9a [2] 94 b5 }

  condition:
    any of them
}