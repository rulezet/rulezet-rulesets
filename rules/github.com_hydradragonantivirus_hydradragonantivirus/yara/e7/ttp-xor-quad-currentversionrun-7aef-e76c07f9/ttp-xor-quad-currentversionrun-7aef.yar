rule TTP_XOR_QUAD_CurrentVersionRun_7aef {
  strings:
    $key_7aef = { 29 80 [2] 0d 8e [2] 26 a2 [2] 08 80 [2] 1c 9b [2] 13 81 [2] 0d 9c [2] 0f 9d [2] 14 9b [2] 08 9c [2] 14 b3 }

  condition:
    any of them
}