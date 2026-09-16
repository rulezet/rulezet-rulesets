rule TTP_XOR_QUAD_CurrentVersionRun_e3ef {
  strings:
    $key_e3ef = { b0 80 [2] 94 8e [2] bf a2 [2] 91 80 [2] 85 9b [2] 8a 81 [2] 94 9c [2] 96 9d [2] 8d 9b [2] 91 9c [2] 8d b3 }

  condition:
    any of them
}