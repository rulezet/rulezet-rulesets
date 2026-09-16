rule TTP_XOR_QUAD_CurrentVersionRun_2c98 {
  strings:
    $key_2c98 = { 7f f7 [2] 5b f9 [2] 70 d5 [2] 5e f7 [2] 4a ec [2] 45 f6 [2] 5b eb [2] 59 ea [2] 42 ec [2] 5e eb [2] 42 c4 }

  condition:
    any of them
}