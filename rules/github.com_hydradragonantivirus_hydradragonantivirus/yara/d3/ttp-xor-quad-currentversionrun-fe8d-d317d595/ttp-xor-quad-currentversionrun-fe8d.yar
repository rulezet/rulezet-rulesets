rule TTP_XOR_QUAD_CurrentVersionRun_fe8d {
  strings:
    $key_fe8d = { ad e2 [2] 89 ec [2] a2 c0 [2] 8c e2 [2] 98 f9 [2] 97 e3 [2] 89 fe [2] 8b ff [2] 90 f9 [2] 8c fe [2] 90 d1 }

  condition:
    any of them
}