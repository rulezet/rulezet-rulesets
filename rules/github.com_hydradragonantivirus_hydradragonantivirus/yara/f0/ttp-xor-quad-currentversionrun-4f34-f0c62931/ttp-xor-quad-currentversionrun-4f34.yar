rule TTP_XOR_QUAD_CurrentVersionRun_4f34 {
  strings:
    $key_4f34 = { 1c 5b [2] 38 55 [2] 13 79 [2] 3d 5b [2] 29 40 [2] 26 5a [2] 38 47 [2] 3a 46 [2] 21 40 [2] 3d 47 [2] 21 68 }

  condition:
    any of them
}