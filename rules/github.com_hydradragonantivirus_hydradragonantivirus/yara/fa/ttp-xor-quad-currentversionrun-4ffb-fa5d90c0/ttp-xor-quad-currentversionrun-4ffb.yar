rule TTP_XOR_QUAD_CurrentVersionRun_4ffb {
  strings:
    $key_4ffb = { 1c 94 [2] 38 9a [2] 13 b6 [2] 3d 94 [2] 29 8f [2] 26 95 [2] 38 88 [2] 3a 89 [2] 21 8f [2] 3d 88 [2] 21 a7 }

  condition:
    any of them
}