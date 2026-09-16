rule TTP_XOR_QUAD_CurrentVersionRun_03ef {
  strings:
    $key_03ef = { 50 80 [2] 74 8e [2] 5f a2 [2] 71 80 [2] 65 9b [2] 6a 81 [2] 74 9c [2] 76 9d [2] 6d 9b [2] 71 9c [2] 6d b3 }

  condition:
    any of them
}