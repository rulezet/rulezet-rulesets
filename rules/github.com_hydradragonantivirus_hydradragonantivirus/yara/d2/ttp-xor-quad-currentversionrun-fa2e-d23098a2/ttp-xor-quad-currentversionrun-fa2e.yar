rule TTP_XOR_QUAD_CurrentVersionRun_fa2e {
  strings:
    $key_fa2e = { a9 41 [2] 8d 4f [2] a6 63 [2] 88 41 [2] 9c 5a [2] 93 40 [2] 8d 5d [2] 8f 5c [2] 94 5a [2] 88 5d [2] 94 72 }

  condition:
    any of them
}