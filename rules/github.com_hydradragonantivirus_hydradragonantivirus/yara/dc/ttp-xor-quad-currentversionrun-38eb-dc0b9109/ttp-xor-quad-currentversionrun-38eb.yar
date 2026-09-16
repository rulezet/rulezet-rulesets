rule TTP_XOR_QUAD_CurrentVersionRun_38eb {
  strings:
    $key_38eb = { 6b 84 [2] 4f 8a [2] 64 a6 [2] 4a 84 [2] 5e 9f [2] 51 85 [2] 4f 98 [2] 4d 99 [2] 56 9f [2] 4a 98 [2] 56 b7 }

  condition:
    any of them
}