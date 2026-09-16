rule TTP_XOR_QUAD_CurrentVersionRun_72fa {
  strings:
    $key_72fa = { 21 95 [2] 05 9b [2] 2e b7 [2] 00 95 [2] 14 8e [2] 1b 94 [2] 05 89 [2] 07 88 [2] 1c 8e [2] 00 89 [2] 1c a6 }

  condition:
    any of them
}