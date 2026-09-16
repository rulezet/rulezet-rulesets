rule TTP_XOR_QUAD_CurrentVersionRun_72ff {
  strings:
    $key_72ff = { 21 90 [2] 05 9e [2] 2e b2 [2] 00 90 [2] 14 8b [2] 1b 91 [2] 05 8c [2] 07 8d [2] 1c 8b [2] 00 8c [2] 1c a3 }

  condition:
    any of them
}