rule TTP_XOR_QUAD_CurrentVersionRun_6af9 {
  strings:
    $key_6af9 = { 39 96 [2] 1d 98 [2] 36 b4 [2] 18 96 [2] 0c 8d [2] 03 97 [2] 1d 8a [2] 1f 8b [2] 04 8d [2] 18 8a [2] 04 a5 }

  condition:
    any of them
}