rule TTP_XOR_QUAD_CurrentVersionRun_7e80 {
  strings:
    $key_7e80 = { 2d ef [2] 09 e1 [2] 22 cd [2] 0c ef [2] 18 f4 [2] 17 ee [2] 09 f3 [2] 0b f2 [2] 10 f4 [2] 0c f3 [2] 10 dc }

  condition:
    any of them
}