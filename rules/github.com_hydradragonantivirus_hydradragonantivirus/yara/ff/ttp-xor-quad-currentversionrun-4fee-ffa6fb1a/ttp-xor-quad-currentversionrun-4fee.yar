rule TTP_XOR_QUAD_CurrentVersionRun_4fee {
  strings:
    $key_4fee = { 1c 81 [2] 38 8f [2] 13 a3 [2] 3d 81 [2] 29 9a [2] 26 80 [2] 38 9d [2] 3a 9c [2] 21 9a [2] 3d 9d [2] 21 b2 }

  condition:
    any of them
}