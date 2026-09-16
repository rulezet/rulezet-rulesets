rule TTP_XOR_QUAD_CurrentVersionRun_2c93 {
  strings:
    $key_2c93 = { 7f fc [2] 5b f2 [2] 70 de [2] 5e fc [2] 4a e7 [2] 45 fd [2] 5b e0 [2] 59 e1 [2] 42 e7 [2] 5e e0 [2] 42 cf }

  condition:
    any of them
}