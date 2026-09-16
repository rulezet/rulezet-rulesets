rule TTP_XOR_QUAD_CurrentVersionRun_4bfb {
  strings:
    $key_4bfb = { 18 94 [2] 3c 9a [2] 17 b6 [2] 39 94 [2] 2d 8f [2] 22 95 [2] 3c 88 [2] 3e 89 [2] 25 8f [2] 39 88 [2] 25 a7 }

  condition:
    any of them
}