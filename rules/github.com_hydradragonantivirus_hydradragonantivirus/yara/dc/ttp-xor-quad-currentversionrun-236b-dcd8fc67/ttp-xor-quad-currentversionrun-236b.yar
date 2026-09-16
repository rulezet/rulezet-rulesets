rule TTP_XOR_QUAD_CurrentVersionRun_236b {
  strings:
    $key_236b = { 70 04 [2] 54 0a [2] 7f 26 [2] 51 04 [2] 45 1f [2] 4a 05 [2] 54 18 [2] 56 19 [2] 4d 1f [2] 51 18 [2] 4d 37 }

  condition:
    any of them
}