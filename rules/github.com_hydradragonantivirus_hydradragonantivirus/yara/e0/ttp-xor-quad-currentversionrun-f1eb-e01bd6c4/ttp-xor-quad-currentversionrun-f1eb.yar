rule TTP_XOR_QUAD_CurrentVersionRun_f1eb {
  strings:
    $key_f1eb = { a2 84 [2] 86 8a [2] ad a6 [2] 83 84 [2] 97 9f [2] 98 85 [2] 86 98 [2] 84 99 [2] 9f 9f [2] 83 98 [2] 9f b7 }

  condition:
    any of them
}