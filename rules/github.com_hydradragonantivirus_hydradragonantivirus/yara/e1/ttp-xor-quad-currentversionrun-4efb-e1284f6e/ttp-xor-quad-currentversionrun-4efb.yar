rule TTP_XOR_QUAD_CurrentVersionRun_4efb {
  strings:
    $key_4efb = { 1d 94 [2] 39 9a [2] 12 b6 [2] 3c 94 [2] 28 8f [2] 27 95 [2] 39 88 [2] 3b 89 [2] 20 8f [2] 3c 88 [2] 20 a7 }

  condition:
    any of them
}