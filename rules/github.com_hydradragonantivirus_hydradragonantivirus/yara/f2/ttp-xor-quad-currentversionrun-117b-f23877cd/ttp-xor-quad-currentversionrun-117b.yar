rule TTP_XOR_QUAD_CurrentVersionRun_117b {
  strings:
    $key_117b = { 42 14 [2] 66 1a [2] 4d 36 [2] 63 14 [2] 77 0f [2] 78 15 [2] 66 08 [2] 64 09 [2] 7f 0f [2] 63 08 [2] 7f 27 }

  condition:
    any of them
}