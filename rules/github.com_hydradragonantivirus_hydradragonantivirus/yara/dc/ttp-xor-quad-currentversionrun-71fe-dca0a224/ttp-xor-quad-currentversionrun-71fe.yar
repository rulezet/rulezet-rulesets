rule TTP_XOR_QUAD_CurrentVersionRun_71fe {
  strings:
    $key_71fe = { 22 91 [2] 06 9f [2] 2d b3 [2] 03 91 [2] 17 8a [2] 18 90 [2] 06 8d [2] 04 8c [2] 1f 8a [2] 03 8d [2] 1f a2 }

  condition:
    any of them
}