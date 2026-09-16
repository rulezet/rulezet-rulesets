rule TTP_XOR_QUAD_CurrentVersionRun_496b {
  strings:
    $key_496b = { 1a 04 [2] 3e 0a [2] 15 26 [2] 3b 04 [2] 2f 1f [2] 20 05 [2] 3e 18 [2] 3c 19 [2] 27 1f [2] 3b 18 [2] 27 37 }

  condition:
    any of them
}