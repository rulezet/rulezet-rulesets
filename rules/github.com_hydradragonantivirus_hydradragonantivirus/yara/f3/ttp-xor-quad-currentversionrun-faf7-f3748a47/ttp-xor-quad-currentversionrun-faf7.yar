rule TTP_XOR_QUAD_CurrentVersionRun_faf7 {
  strings:
    $key_faf7 = { a9 98 [2] 8d 96 [2] a6 ba [2] 88 98 [2] 9c 83 [2] 93 99 [2] 8d 84 [2] 8f 85 [2] 94 83 [2] 88 84 [2] 94 ab }

  condition:
    any of them
}