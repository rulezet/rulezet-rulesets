rule TTP_XOR_QUAD_CurrentVersionRun_3419 {
  strings:
    $key_3419 = { 67 76 [2] 43 78 [2] 68 54 [2] 46 76 [2] 52 6d [2] 5d 77 [2] 43 6a [2] 41 6b [2] 5a 6d [2] 46 6a [2] 5a 45 }

  condition:
    any of them
}