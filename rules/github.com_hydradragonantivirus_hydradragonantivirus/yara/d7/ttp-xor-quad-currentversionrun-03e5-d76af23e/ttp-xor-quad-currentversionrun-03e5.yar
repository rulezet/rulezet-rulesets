rule TTP_XOR_QUAD_CurrentVersionRun_03e5 {
  strings:
    $key_03e5 = { 50 8a [2] 74 84 [2] 5f a8 [2] 71 8a [2] 65 91 [2] 6a 8b [2] 74 96 [2] 76 97 [2] 6d 91 [2] 71 96 [2] 6d b9 }

  condition:
    any of them
}