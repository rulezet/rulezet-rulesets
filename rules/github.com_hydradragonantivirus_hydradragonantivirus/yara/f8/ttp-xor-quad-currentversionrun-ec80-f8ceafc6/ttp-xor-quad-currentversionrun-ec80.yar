rule TTP_XOR_QUAD_CurrentVersionRun_ec80 {
  strings:
    $key_ec80 = { bf ef [2] 9b e1 [2] b0 cd [2] 9e ef [2] 8a f4 [2] 85 ee [2] 9b f3 [2] 99 f2 [2] 82 f4 [2] 9e f3 [2] 82 dc }

  condition:
    any of them
}