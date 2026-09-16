rule TTP_XOR_QUAD_CurrentVersionRun_10ff {
  strings:
    $key_10ff = { 43 90 [2] 67 9e [2] 4c b2 [2] 62 90 [2] 76 8b [2] 79 91 [2] 67 8c [2] 65 8d [2] 7e 8b [2] 62 8c [2] 7e a3 }

  condition:
    any of them
}