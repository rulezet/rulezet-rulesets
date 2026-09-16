rule TTP_XOR_QUAD_CurrentVersionRun_e8ff {
  strings:
    $key_e8ff = { bb 90 [2] 9f 9e [2] b4 b2 [2] 9a 90 [2] 8e 8b [2] 81 91 [2] 9f 8c [2] 9d 8d [2] 86 8b [2] 9a 8c [2] 86 a3 }

  condition:
    any of them
}