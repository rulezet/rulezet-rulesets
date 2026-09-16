rule TTP_XOR_QUAD_CurrentVersionRun_54fe {
  strings:
    $key_54fe = { 07 91 [2] 23 9f [2] 08 b3 [2] 26 91 [2] 32 8a [2] 3d 90 [2] 23 8d [2] 21 8c [2] 3a 8a [2] 26 8d [2] 3a a2 }

  condition:
    any of them
}