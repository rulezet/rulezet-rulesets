rule TTP_XOR_QUAD_CurrentVersionRun_177b {
  strings:
    $key_177b = { 44 14 [2] 60 1a [2] 4b 36 [2] 65 14 [2] 71 0f [2] 7e 15 [2] 60 08 [2] 62 09 [2] 79 0f [2] 65 08 [2] 79 27 }

  condition:
    any of them
}