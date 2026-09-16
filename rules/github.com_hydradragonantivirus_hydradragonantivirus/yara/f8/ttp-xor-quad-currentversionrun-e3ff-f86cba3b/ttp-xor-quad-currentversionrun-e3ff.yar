rule TTP_XOR_QUAD_CurrentVersionRun_e3ff {
  strings:
    $key_e3ff = { b0 90 [2] 94 9e [2] bf b2 [2] 91 90 [2] 85 8b [2] 8a 91 [2] 94 8c [2] 96 8d [2] 8d 8b [2] 91 8c [2] 8d a3 }

  condition:
    any of them
}