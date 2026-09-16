rule TTP_XOR_QUAD_CurrentVersionRun_fe8a {
  strings:
    $key_fe8a = { ad e5 [2] 89 eb [2] a2 c7 [2] 8c e5 [2] 98 fe [2] 97 e4 [2] 89 f9 [2] 8b f8 [2] 90 fe [2] 8c f9 [2] 90 d6 }

  condition:
    any of them
}