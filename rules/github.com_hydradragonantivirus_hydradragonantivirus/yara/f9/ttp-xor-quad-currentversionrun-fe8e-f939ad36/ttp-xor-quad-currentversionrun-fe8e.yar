rule TTP_XOR_QUAD_CurrentVersionRun_fe8e {
  strings:
    $key_fe8e = { ad e1 [2] 89 ef [2] a2 c3 [2] 8c e1 [2] 98 fa [2] 97 e0 [2] 89 fd [2] 8b fc [2] 90 fa [2] 8c fd [2] 90 d2 }

  condition:
    any of them
}