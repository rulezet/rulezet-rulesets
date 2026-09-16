rule TTP_XOR_QUAD_CurrentVersionRun_0f3b {
  strings:
    $key_0f3b = { 5c 54 [2] 78 5a [2] 53 76 [2] 7d 54 [2] 69 4f [2] 66 55 [2] 78 48 [2] 7a 49 [2] 61 4f [2] 7d 48 [2] 61 67 }

  condition:
    any of them
}