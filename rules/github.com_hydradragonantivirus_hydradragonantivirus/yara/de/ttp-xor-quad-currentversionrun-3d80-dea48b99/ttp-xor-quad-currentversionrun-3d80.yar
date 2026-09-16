rule TTP_XOR_QUAD_CurrentVersionRun_3d80 {
  strings:
    $key_3d80 = { 6e ef [2] 4a e1 [2] 61 cd [2] 4f ef [2] 5b f4 [2] 54 ee [2] 4a f3 [2] 48 f2 [2] 53 f4 [2] 4f f3 [2] 53 dc }

  condition:
    any of them
}