rule TTP_XOR_QUAD_CurrentVersionRun_7a2e {
  strings:
    $key_7a2e = { 29 41 [2] 0d 4f [2] 26 63 [2] 08 41 [2] 1c 5a [2] 13 40 [2] 0d 5d [2] 0f 5c [2] 14 5a [2] 08 5d [2] 14 72 }

  condition:
    any of them
}