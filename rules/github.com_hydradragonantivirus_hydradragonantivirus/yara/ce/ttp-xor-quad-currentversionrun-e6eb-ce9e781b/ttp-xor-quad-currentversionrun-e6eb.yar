rule TTP_XOR_QUAD_CurrentVersionRun_e6eb {
  strings:
    $key_e6eb = { b5 84 [2] 91 8a [2] ba a6 [2] 94 84 [2] 80 9f [2] 8f 85 [2] 91 98 [2] 93 99 [2] 88 9f [2] 94 98 [2] 88 b7 }

  condition:
    any of them
}