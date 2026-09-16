rule TTP_XOR_QUAD_CurrentVersionRun_1980 {
  strings:
    $key_1980 = { 4a ef [2] 6e e1 [2] 45 cd [2] 6b ef [2] 7f f4 [2] 70 ee [2] 6e f3 [2] 6c f2 [2] 77 f4 [2] 6b f3 [2] 77 dc }

  condition:
    any of them
}