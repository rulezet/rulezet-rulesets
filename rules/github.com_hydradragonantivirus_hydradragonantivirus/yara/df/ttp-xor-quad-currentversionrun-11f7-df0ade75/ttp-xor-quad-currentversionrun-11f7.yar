rule TTP_XOR_QUAD_CurrentVersionRun_11f7 {
  strings:
    $key_11f7 = { 42 98 [2] 66 96 [2] 4d ba [2] 63 98 [2] 77 83 [2] 78 99 [2] 66 84 [2] 64 85 [2] 7f 83 [2] 63 84 [2] 7f ab }

  condition:
    any of them
}