rule TTP_XOR_QUAD_CurrentVersionRun_157b {
  strings:
    $key_157b = { 46 14 [2] 62 1a [2] 49 36 [2] 67 14 [2] 73 0f [2] 7c 15 [2] 62 08 [2] 60 09 [2] 7b 0f [2] 67 08 [2] 7b 27 }

  condition:
    any of them
}