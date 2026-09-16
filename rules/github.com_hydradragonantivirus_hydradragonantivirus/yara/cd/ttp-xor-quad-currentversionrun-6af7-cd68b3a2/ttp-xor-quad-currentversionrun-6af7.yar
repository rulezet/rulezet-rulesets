rule TTP_XOR_QUAD_CurrentVersionRun_6af7 {
  strings:
    $key_6af7 = { 39 98 [2] 1d 96 [2] 36 ba [2] 18 98 [2] 0c 83 [2] 03 99 [2] 1d 84 [2] 1f 85 [2] 04 83 [2] 18 84 [2] 04 ab }

  condition:
    any of them
}