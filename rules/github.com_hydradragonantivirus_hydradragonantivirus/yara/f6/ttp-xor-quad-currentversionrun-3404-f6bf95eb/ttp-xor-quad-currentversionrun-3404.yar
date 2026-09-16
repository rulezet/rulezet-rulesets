rule TTP_XOR_QUAD_CurrentVersionRun_3404 {
  strings:
    $key_3404 = { 67 6b [2] 43 65 [2] 68 49 [2] 46 6b [2] 52 70 [2] 5d 6a [2] 43 77 [2] 41 76 [2] 5a 70 [2] 46 77 [2] 5a 58 }

  condition:
    any of them
}