rule TTP_XOR_QUAD_CurrentVersionRun_03eb {
  strings:
    $key_03eb = { 50 84 [2] 74 8a [2] 5f a6 [2] 71 84 [2] 65 9f [2] 6a 85 [2] 74 98 [2] 76 99 [2] 6d 9f [2] 71 98 [2] 6d b7 }

  condition:
    any of them
}