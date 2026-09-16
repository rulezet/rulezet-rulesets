rule TTP_XOR_QUAD_CurrentVersionRun_06ff {
  strings:
    $key_06ff = { 55 90 [2] 71 9e [2] 5a b2 [2] 74 90 [2] 60 8b [2] 6f 91 [2] 71 8c [2] 73 8d [2] 68 8b [2] 74 8c [2] 68 a3 }

  condition:
    any of them
}