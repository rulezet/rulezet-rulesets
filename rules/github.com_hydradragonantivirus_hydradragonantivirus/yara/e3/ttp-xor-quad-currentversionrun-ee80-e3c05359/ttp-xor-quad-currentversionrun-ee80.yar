rule TTP_XOR_QUAD_CurrentVersionRun_ee80 {
  strings:
    $key_ee80 = { bd ef [2] 99 e1 [2] b2 cd [2] 9c ef [2] 88 f4 [2] 87 ee [2] 99 f3 [2] 9b f2 [2] 80 f4 [2] 9c f3 [2] 80 dc }

  condition:
    any of them
}