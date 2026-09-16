rule TTP_XOR_QUAD_CurrentVersionRun_13e5 {
  strings:
    $key_13e5 = { 40 8a [2] 64 84 [2] 4f a8 [2] 61 8a [2] 75 91 [2] 7a 8b [2] 64 96 [2] 66 97 [2] 7d 91 [2] 61 96 [2] 7d b9 }

  condition:
    any of them
}