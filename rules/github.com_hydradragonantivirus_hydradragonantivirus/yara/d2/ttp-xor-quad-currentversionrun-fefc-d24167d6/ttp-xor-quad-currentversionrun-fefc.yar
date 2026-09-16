rule TTP_XOR_QUAD_CurrentVersionRun_fefc {
  strings:
    $key_fefc = { ad 93 [2] 89 9d [2] a2 b1 [2] 8c 93 [2] 98 88 [2] 97 92 [2] 89 8f [2] 8b 8e [2] 90 88 [2] 8c 8f [2] 90 a0 }

  condition:
    any of them
}