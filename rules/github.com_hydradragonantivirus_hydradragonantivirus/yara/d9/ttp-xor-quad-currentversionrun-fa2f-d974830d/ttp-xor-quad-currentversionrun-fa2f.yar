rule TTP_XOR_QUAD_CurrentVersionRun_fa2f {
  strings:
    $key_fa2f = { a9 40 [2] 8d 4e [2] a6 62 [2] 88 40 [2] 9c 5b [2] 93 41 [2] 8d 5c [2] 8f 5d [2] 94 5b [2] 88 5c [2] 94 73 }

  condition:
    any of them
}