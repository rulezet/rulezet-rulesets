rule TTP_XOR_QUAD_CurrentVersionRun_fe8f {
  strings:
    $key_fe8f = { ad e0 [2] 89 ee [2] a2 c2 [2] 8c e0 [2] 98 fb [2] 97 e1 [2] 89 fc [2] 8b fd [2] 90 fb [2] 8c fc [2] 90 d3 }

  condition:
    any of them
}