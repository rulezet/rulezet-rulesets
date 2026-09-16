rule TTP_XOR_QUAD_CurrentVersionRun_ab71 {
  strings:
    $key_ab71 = { f8 1e [2] dc 10 [2] f7 3c [2] d9 1e [2] cd 05 [2] c2 1f [2] dc 02 [2] de 03 [2] c5 05 [2] d9 02 [2] c5 2d }

  condition:
    any of them
}