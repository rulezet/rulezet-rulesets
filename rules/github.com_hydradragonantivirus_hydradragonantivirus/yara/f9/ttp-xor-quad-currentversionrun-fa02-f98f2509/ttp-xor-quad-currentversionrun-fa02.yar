rule TTP_XOR_QUAD_CurrentVersionRun_fa02 {
  strings:
    $key_fa02 = { a9 6d [2] 8d 63 [2] a6 4f [2] 88 6d [2] 9c 76 [2] 93 6c [2] 8d 71 [2] 8f 70 [2] 94 76 [2] 88 71 [2] 94 5e }

  condition:
    any of them
}