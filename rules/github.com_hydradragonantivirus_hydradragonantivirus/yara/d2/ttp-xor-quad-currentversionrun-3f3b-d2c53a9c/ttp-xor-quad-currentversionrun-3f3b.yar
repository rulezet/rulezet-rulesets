rule TTP_XOR_QUAD_CurrentVersionRun_3f3b {
  strings:
    $key_3f3b = { 6c 54 [2] 48 5a [2] 63 76 [2] 4d 54 [2] 59 4f [2] 56 55 [2] 48 48 [2] 4a 49 [2] 51 4f [2] 4d 48 [2] 51 67 }

  condition:
    any of them
}