rule TTP_XOR_QUAD_CurrentVersionRun_237d {
  strings:
    $key_237d = { 70 12 [2] 54 1c [2] 7f 30 [2] 51 12 [2] 45 09 [2] 4a 13 [2] 54 0e [2] 56 0f [2] 4d 09 [2] 51 0e [2] 4d 21 }

  condition:
    any of them
}