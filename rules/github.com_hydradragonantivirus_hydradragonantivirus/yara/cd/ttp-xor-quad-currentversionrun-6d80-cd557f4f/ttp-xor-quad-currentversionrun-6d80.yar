rule TTP_XOR_QUAD_CurrentVersionRun_6d80 {
  strings:
    $key_6d80 = { 3e ef [2] 1a e1 [2] 31 cd [2] 1f ef [2] 0b f4 [2] 04 ee [2] 1a f3 [2] 18 f2 [2] 03 f4 [2] 1f f3 [2] 03 dc }

  condition:
    any of them
}