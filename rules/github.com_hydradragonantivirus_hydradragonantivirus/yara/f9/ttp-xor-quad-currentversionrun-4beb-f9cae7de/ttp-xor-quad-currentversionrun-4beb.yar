rule TTP_XOR_QUAD_CurrentVersionRun_4beb {
  strings:
    $key_4beb = { 18 84 [2] 3c 8a [2] 17 a6 [2] 39 84 [2] 2d 9f [2] 22 85 [2] 3c 98 [2] 3e 99 [2] 25 9f [2] 39 98 [2] 25 b7 }

  condition:
    any of them
}