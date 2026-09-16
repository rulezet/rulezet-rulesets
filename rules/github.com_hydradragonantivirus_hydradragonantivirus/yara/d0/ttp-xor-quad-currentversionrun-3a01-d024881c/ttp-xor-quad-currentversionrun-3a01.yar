rule TTP_XOR_QUAD_CurrentVersionRun_3a01 {
  strings:
    $key_3a01 = { 69 6e [2] 4d 60 [2] 66 4c [2] 48 6e [2] 5c 75 [2] 53 6f [2] 4d 72 [2] 4f 73 [2] 54 75 [2] 48 72 [2] 54 5d }

  condition:
    any of them
}