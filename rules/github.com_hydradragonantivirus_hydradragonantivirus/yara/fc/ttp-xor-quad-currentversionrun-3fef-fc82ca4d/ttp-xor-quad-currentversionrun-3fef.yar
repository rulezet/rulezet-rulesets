rule TTP_XOR_QUAD_CurrentVersionRun_3fef {
  strings:
    $key_3fef = { 6c 80 [2] 48 8e [2] 63 a2 [2] 4d 80 [2] 59 9b [2] 56 81 [2] 48 9c [2] 4a 9d [2] 51 9b [2] 4d 9c [2] 51 b3 }

  condition:
    any of them
}