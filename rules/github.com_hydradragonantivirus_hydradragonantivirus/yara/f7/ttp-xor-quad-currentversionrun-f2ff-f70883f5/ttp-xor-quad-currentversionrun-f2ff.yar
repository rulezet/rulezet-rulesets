rule TTP_XOR_QUAD_CurrentVersionRun_f2ff {
  strings:
    $key_f2ff = { a1 90 [2] 85 9e [2] ae b2 [2] 80 90 [2] 94 8b [2] 9b 91 [2] 85 8c [2] 87 8d [2] 9c 8b [2] 80 8c [2] 9c a3 }

  condition:
    any of them
}