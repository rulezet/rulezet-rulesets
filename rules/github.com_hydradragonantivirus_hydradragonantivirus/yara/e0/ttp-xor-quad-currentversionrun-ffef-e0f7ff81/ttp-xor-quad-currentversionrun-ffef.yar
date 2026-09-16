rule TTP_XOR_QUAD_CurrentVersionRun_ffef {
  strings:
    $key_ffef = { ac 80 [2] 88 8e [2] a3 a2 [2] 8d 80 [2] 99 9b [2] 96 81 [2] 88 9c [2] 8a 9d [2] 91 9b [2] 8d 9c [2] 91 b3 }

  condition:
    any of them
}