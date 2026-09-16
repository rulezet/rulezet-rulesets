rule TTP_XOR_QUAD_CurrentVersionRun_44f7 {
  strings:
    $key_44f7 = { 17 98 [2] 33 96 [2] 18 ba [2] 36 98 [2] 22 83 [2] 2d 99 [2] 33 84 [2] 31 85 [2] 2a 83 [2] 36 84 [2] 2a ab }

  condition:
    any of them
}