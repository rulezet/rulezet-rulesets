rule TTP_XOR_QUAD_CurrentVersionRun_6ae5 {
  strings:
    $key_6ae5 = { 39 8a [2] 1d 84 [2] 36 a8 [2] 18 8a [2] 0c 91 [2] 03 8b [2] 1d 96 [2] 1f 97 [2] 04 91 [2] 18 96 [2] 04 b9 }

  condition:
    any of them
}