rule TTP_XOR_QUAD_CurrentVersionRun_fe9f {
  strings:
    $key_fe9f = { ad f0 [2] 89 fe [2] a2 d2 [2] 8c f0 [2] 98 eb [2] 97 f1 [2] 89 ec [2] 8b ed [2] 90 eb [2] 8c ec [2] 90 c3 }

  condition:
    any of them
}