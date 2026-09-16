rule TTP_XOR_QUAD_CurrentVersionRun_f325 {
  strings:
    $key_f325 = { a0 4a [2] 84 44 [2] af 68 [2] 81 4a [2] 95 51 [2] 9a 4b [2] 84 56 [2] 86 57 [2] 9d 51 [2] 81 56 [2] 9d 79 }

  condition:
    any of them
}