rule TTP_XOR_QUAD_CurrentVersionRun_2e80 {
  strings:
    $key_2e80 = { 7d ef [2] 59 e1 [2] 72 cd [2] 5c ef [2] 48 f4 [2] 47 ee [2] 59 f3 [2] 5b f2 [2] 40 f4 [2] 5c f3 [2] 40 dc }

  condition:
    any of them
}