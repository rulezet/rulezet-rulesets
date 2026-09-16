rule TTP_XOR_QUAD_CurrentVersionRun_e7ff {
  strings:
    $key_e7ff = { b4 90 [2] 90 9e [2] bb b2 [2] 95 90 [2] 81 8b [2] 8e 91 [2] 90 8c [2] 92 8d [2] 89 8b [2] 95 8c [2] 89 a3 }

  condition:
    any of them
}