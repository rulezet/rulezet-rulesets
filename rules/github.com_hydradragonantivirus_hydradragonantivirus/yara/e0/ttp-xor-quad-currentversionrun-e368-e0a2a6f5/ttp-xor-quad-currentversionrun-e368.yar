rule TTP_XOR_QUAD_CurrentVersionRun_e368 {
  strings:
    $key_e368 = { b0 07 [2] 94 09 [2] bf 25 [2] 91 07 [2] 85 1c [2] 8a 06 [2] 94 1b [2] 96 1a [2] 8d 1c [2] 91 1b [2] 8d 34 }

  condition:
    any of them
}