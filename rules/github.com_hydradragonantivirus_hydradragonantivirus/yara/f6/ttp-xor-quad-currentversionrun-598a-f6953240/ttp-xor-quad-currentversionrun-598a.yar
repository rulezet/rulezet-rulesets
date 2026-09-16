rule TTP_XOR_QUAD_CurrentVersionRun_598a {
  strings:
    $key_598a = { 0a e5 [2] 2e eb [2] 05 c7 [2] 2b e5 [2] 3f fe [2] 30 e4 [2] 2e f9 [2] 2c f8 [2] 37 fe [2] 2b f9 [2] 37 d6 }

  condition:
    any of them
}