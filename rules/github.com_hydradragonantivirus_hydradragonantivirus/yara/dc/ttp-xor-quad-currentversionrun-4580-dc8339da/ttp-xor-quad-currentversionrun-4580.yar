rule TTP_XOR_QUAD_CurrentVersionRun_4580 {
  strings:
    $key_4580 = { 16 ef [2] 32 e1 [2] 19 cd [2] 37 ef [2] 23 f4 [2] 2c ee [2] 32 f3 [2] 30 f2 [2] 2b f4 [2] 37 f3 [2] 2b dc }

  condition:
    any of them
}