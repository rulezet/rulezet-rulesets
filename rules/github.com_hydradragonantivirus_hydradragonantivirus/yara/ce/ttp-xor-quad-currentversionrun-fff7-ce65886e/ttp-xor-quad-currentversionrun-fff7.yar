rule TTP_XOR_QUAD_CurrentVersionRun_fff7 {
  strings:
    $key_fff7 = { ac 98 [2] 88 96 [2] a3 ba [2] 8d 98 [2] 99 83 [2] 96 99 [2] 88 84 [2] 8a 85 [2] 91 83 [2] 8d 84 [2] 91 ab }

  condition:
    any of them
}