rule TTP_XOR_QUAD_CurrentVersionRun_17eb {
  strings:
    $key_17eb = { 44 84 [2] 60 8a [2] 4b a6 [2] 65 84 [2] 71 9f [2] 7e 85 [2] 60 98 [2] 62 99 [2] 79 9f [2] 65 98 [2] 79 b7 }

  condition:
    any of them
}