rule TTP_XOR_QUAD_CurrentVersionRun_faeb {
  strings:
    $key_faeb = { a9 84 [2] 8d 8a [2] a6 a6 [2] 88 84 [2] 9c 9f [2] 93 85 [2] 8d 98 [2] 8f 99 [2] 94 9f [2] 88 98 [2] 94 b7 }

  condition:
    any of them
}