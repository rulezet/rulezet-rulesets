rule TTP_XOR_QUAD_CurrentVersionRun_fe87 {
  strings:
    $key_fe87 = { ad e8 [2] 89 e6 [2] a2 ca [2] 8c e8 [2] 98 f3 [2] 97 e9 [2] 89 f4 [2] 8b f5 [2] 90 f3 [2] 8c f4 [2] 90 db }

  condition:
    any of them
}