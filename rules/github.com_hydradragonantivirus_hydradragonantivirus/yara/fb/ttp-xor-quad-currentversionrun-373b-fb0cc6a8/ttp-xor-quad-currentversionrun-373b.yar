rule TTP_XOR_QUAD_CurrentVersionRun_373b {
  strings:
    $key_373b = { 64 54 [2] 40 5a [2] 6b 76 [2] 45 54 [2] 51 4f [2] 5e 55 [2] 40 48 [2] 42 49 [2] 59 4f [2] 45 48 [2] 59 67 }

  condition:
    any of them
}