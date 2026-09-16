rule TTP_XOR_QUAD_CurrentVersionRun_3fe5 {
  strings:
    $key_3fe5 = { 6c 8a [2] 48 84 [2] 63 a8 [2] 4d 8a [2] 59 91 [2] 56 8b [2] 48 96 [2] 4a 97 [2] 51 91 [2] 4d 96 [2] 51 b9 }

  condition:
    any of them
}