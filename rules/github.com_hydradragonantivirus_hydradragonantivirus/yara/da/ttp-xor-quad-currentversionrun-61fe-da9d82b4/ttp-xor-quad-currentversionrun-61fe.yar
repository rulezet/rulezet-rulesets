rule TTP_XOR_QUAD_CurrentVersionRun_61fe {
  strings:
    $key_61fe = { 32 91 [2] 16 9f [2] 3d b3 [2] 13 91 [2] 07 8a [2] 08 90 [2] 16 8d [2] 14 8c [2] 0f 8a [2] 13 8d [2] 0f a2 }

  condition:
    any of them
}