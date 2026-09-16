rule TTP_XOR_QUAD_CurrentVersionRun_65ff {
  strings:
    $key_65ff = { 36 90 [2] 12 9e [2] 39 b2 [2] 17 90 [2] 03 8b [2] 0c 91 [2] 12 8c [2] 10 8d [2] 0b 8b [2] 17 8c [2] 0b a3 }

  condition:
    any of them
}