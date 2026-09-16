rule TTP_XOR_QUAD_CurrentVersionRun_1fe5 {
  strings:
    $key_1fe5 = { 4c 8a [2] 68 84 [2] 43 a8 [2] 6d 8a [2] 79 91 [2] 76 8b [2] 68 96 [2] 6a 97 [2] 71 91 [2] 6d 96 [2] 71 b9 }

  condition:
    any of them
}