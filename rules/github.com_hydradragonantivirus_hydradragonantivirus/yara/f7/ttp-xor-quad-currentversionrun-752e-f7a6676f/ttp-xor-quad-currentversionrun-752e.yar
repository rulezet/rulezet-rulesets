rule TTP_XOR_QUAD_CurrentVersionRun_752e {
  strings:
    $key_752e = { 26 41 [2] 02 4f [2] 29 63 [2] 07 41 [2] 13 5a [2] 1c 40 [2] 02 5d [2] 00 5c [2] 1b 5a [2] 07 5d [2] 1b 72 }

  condition:
    any of them
}