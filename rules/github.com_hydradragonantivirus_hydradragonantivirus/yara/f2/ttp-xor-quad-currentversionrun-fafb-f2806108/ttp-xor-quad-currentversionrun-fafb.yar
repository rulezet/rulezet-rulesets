rule TTP_XOR_QUAD_CurrentVersionRun_fafb {
  strings:
    $key_fafb = { a9 94 [2] 8d 9a [2] a6 b6 [2] 88 94 [2] 9c 8f [2] 93 95 [2] 8d 88 [2] 8f 89 [2] 94 8f [2] 88 88 [2] 94 a7 }

  condition:
    any of them
}