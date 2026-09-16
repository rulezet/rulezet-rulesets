rule TTP_XOR_QUAD_CurrentVersionRun_60f0 {
  strings:
    $key_60f0 = { 33 9f [2] 17 91 [2] 3c bd [2] 12 9f [2] 06 84 [2] 09 9e [2] 17 83 [2] 15 82 [2] 0e 84 [2] 12 83 [2] 0e ac }

  condition:
    any of them
}