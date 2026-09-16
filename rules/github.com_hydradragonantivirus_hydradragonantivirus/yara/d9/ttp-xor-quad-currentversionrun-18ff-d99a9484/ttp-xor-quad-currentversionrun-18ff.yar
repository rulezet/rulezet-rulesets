rule TTP_XOR_QUAD_CurrentVersionRun_18ff {
  strings:
    $key_18ff = { 4b 90 [2] 6f 9e [2] 44 b2 [2] 6a 90 [2] 7e 8b [2] 71 91 [2] 6f 8c [2] 6d 8d [2] 76 8b [2] 6a 8c [2] 76 a3 }

  condition:
    any of them
}