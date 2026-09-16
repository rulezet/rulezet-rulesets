rule TTP_XOR_QUAD_CurrentVersionRun_feeb {
  strings:
    $key_feeb = { ad 84 [2] 89 8a [2] a2 a6 [2] 8c 84 [2] 98 9f [2] 97 85 [2] 89 98 [2] 8b 99 [2] 90 9f [2] 8c 98 [2] 90 b7 }

  condition:
    any of them
}