rule TTP_XOR_QUAD_CurrentVersionRun_3a2c {
  strings:
    $key_3a2c = { 69 43 [2] 4d 4d [2] 66 61 [2] 48 43 [2] 5c 58 [2] 53 42 [2] 4d 5f [2] 4f 5e [2] 54 58 [2] 48 5f [2] 54 70 }

  condition:
    any of them
}