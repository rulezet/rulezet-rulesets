rule TTP_XOR_QUAD_CurrentVersionRun_6431 {
  strings:
    $key_6431 = { 37 5e [2] 13 50 [2] 38 7c [2] 16 5e [2] 02 45 [2] 0d 5f [2] 13 42 [2] 11 43 [2] 0a 45 [2] 16 42 [2] 0a 6d }

  condition:
    any of them
}