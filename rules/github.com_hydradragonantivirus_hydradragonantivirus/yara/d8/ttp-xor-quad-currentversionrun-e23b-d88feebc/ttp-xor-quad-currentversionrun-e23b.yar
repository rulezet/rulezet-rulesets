rule TTP_XOR_QUAD_CurrentVersionRun_e23b {
  strings:
    $key_e23b = { b1 54 [2] 95 5a [2] be 76 [2] 90 54 [2] 84 4f [2] 8b 55 [2] 95 48 [2] 97 49 [2] 8c 4f [2] 90 48 [2] 8c 67 }

  condition:
    any of them
}