rule TTP_XOR_QUAD_CurrentVersionRun_4aef {
  strings:
    $key_4aef = { 19 80 [2] 3d 8e [2] 16 a2 [2] 38 80 [2] 2c 9b [2] 23 81 [2] 3d 9c [2] 3f 9d [2] 24 9b [2] 38 9c [2] 24 b3 }

  condition:
    any of them
}