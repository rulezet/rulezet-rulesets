rule TTP_XOR_QUAD_CurrentVersionRun_fe9d {
  strings:
    $key_fe9d = { ad f2 [2] 89 fc [2] a2 d0 [2] 8c f2 [2] 98 e9 [2] 97 f3 [2] 89 ee [2] 8b ef [2] 90 e9 [2] 8c ee [2] 90 c1 }

  condition:
    any of them
}