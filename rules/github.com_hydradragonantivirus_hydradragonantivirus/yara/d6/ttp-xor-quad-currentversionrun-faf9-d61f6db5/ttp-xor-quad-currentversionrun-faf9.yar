rule TTP_XOR_QUAD_CurrentVersionRun_faf9 {
  strings:
    $key_faf9 = { a9 96 [2] 8d 98 [2] a6 b4 [2] 88 96 [2] 9c 8d [2] 93 97 [2] 8d 8a [2] 8f 8b [2] 94 8d [2] 88 8a [2] 94 a5 }

  condition:
    any of them
}