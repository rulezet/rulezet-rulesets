rule TTP_XOR_QUAD_CurrentVersionRun_fa2a {
  strings:
    $key_fa2a = { a9 45 [2] 8d 4b [2] a6 67 [2] 88 45 [2] 9c 5e [2] 93 44 [2] 8d 59 [2] 8f 58 [2] 94 5e [2] 88 59 [2] 94 76 }

  condition:
    any of them
}