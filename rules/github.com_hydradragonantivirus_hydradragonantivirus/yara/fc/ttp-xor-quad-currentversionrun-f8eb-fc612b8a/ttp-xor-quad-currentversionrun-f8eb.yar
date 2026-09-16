rule TTP_XOR_QUAD_CurrentVersionRun_f8eb {
  strings:
    $key_f8eb = { ab 84 [2] 8f 8a [2] a4 a6 [2] 8a 84 [2] 9e 9f [2] 91 85 [2] 8f 98 [2] 8d 99 [2] 96 9f [2] 8a 98 [2] 96 b7 }

  condition:
    any of them
}