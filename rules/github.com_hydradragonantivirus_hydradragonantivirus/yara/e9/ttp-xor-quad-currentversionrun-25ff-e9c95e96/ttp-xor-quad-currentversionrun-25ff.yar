rule TTP_XOR_QUAD_CurrentVersionRun_25ff {
  strings:
    $key_25ff = { 76 90 [2] 52 9e [2] 79 b2 [2] 57 90 [2] 43 8b [2] 4c 91 [2] 52 8c [2] 50 8d [2] 4b 8b [2] 57 8c [2] 4b a3 }

  condition:
    any of them
}