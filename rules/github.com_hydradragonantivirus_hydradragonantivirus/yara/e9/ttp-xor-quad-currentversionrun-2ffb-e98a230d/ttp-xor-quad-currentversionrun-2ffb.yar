rule TTP_XOR_QUAD_CurrentVersionRun_2ffb {
  strings:
    $key_2ffb = { 7c 94 [2] 58 9a [2] 73 b6 [2] 5d 94 [2] 49 8f [2] 46 95 [2] 58 88 [2] 5a 89 [2] 41 8f [2] 5d 88 [2] 41 a7 }

  condition:
    any of them
}