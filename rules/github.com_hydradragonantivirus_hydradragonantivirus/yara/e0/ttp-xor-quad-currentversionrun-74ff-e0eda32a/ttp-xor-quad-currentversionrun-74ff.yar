rule TTP_XOR_QUAD_CurrentVersionRun_74ff {
  strings:
    $key_74ff = { 27 90 [2] 03 9e [2] 28 b2 [2] 06 90 [2] 12 8b [2] 1d 91 [2] 03 8c [2] 01 8d [2] 1a 8b [2] 06 8c [2] 1a a3 }

  condition:
    any of them
}