rule TTP_XOR_QUAD_CurrentVersionRun_3a2e {
  strings:
    $key_3a2e = { 69 41 [2] 4d 4f [2] 66 63 [2] 48 41 [2] 5c 5a [2] 53 40 [2] 4d 5d [2] 4f 5c [2] 54 5a [2] 48 5d [2] 54 72 }

  condition:
    any of them
}