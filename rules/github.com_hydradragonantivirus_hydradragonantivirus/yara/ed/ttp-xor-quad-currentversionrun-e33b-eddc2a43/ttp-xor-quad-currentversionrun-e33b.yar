rule TTP_XOR_QUAD_CurrentVersionRun_e33b {
  strings:
    $key_e33b = { b0 54 [2] 94 5a [2] bf 76 [2] 91 54 [2] 85 4f [2] 8a 55 [2] 94 48 [2] 96 49 [2] 8d 4f [2] 91 48 [2] 8d 67 }

  condition:
    any of them
}