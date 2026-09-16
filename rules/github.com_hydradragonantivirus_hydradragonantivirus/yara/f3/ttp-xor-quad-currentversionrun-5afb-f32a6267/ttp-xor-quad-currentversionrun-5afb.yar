rule TTP_XOR_QUAD_CurrentVersionRun_5afb {
  strings:
    $key_5afb = { 09 94 [2] 2d 9a [2] 06 b6 [2] 28 94 [2] 3c 8f [2] 33 95 [2] 2d 88 [2] 2f 89 [2] 34 8f [2] 28 88 [2] 34 a7 }

  condition:
    any of them
}