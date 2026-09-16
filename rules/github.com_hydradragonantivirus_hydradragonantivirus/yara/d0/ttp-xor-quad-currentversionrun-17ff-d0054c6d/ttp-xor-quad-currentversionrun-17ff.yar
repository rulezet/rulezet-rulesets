rule TTP_XOR_QUAD_CurrentVersionRun_17ff {
  strings:
    $key_17ff = { 44 90 [2] 60 9e [2] 4b b2 [2] 65 90 [2] 71 8b [2] 7e 91 [2] 60 8c [2] 62 8d [2] 79 8b [2] 65 8c [2] 79 a3 }

  condition:
    any of them
}