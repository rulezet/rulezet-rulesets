rule TTP_XOR_QUAD_CurrentVersionRun_fa1c {
  strings:
    $key_fa1c = { a9 73 [2] 8d 7d [2] a6 51 [2] 88 73 [2] 9c 68 [2] 93 72 [2] 8d 6f [2] 8f 6e [2] 94 68 [2] 88 6f [2] 94 40 }

  condition:
    any of them
}