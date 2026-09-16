rule TTP_XOR_QUAD_CurrentVersionRun_353b {
  strings:
    $key_353b = { 66 54 [2] 42 5a [2] 69 76 [2] 47 54 [2] 53 4f [2] 5c 55 [2] 42 48 [2] 40 49 [2] 5b 4f [2] 47 48 [2] 5b 67 }

  condition:
    any of them
}