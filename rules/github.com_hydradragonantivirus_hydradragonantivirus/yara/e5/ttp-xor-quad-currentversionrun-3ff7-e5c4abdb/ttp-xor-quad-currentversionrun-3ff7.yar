rule TTP_XOR_QUAD_CurrentVersionRun_3ff7 {
  strings:
    $key_3ff7 = { 6c 98 [2] 48 96 [2] 63 ba [2] 4d 98 [2] 59 83 [2] 56 99 [2] 48 84 [2] 4a 85 [2] 51 83 [2] 4d 84 [2] 51 ab }

  condition:
    any of them
}