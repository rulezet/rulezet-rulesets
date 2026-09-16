rule TTP_XOR_QUAD_CurrentVersionRun_f9fb {
  strings:
    $key_f9fb = { aa 94 [2] 8e 9a [2] a5 b6 [2] 8b 94 [2] 9f 8f [2] 90 95 [2] 8e 88 [2] 8c 89 [2] 97 8f [2] 8b 88 [2] 97 a7 }

  condition:
    any of them
}