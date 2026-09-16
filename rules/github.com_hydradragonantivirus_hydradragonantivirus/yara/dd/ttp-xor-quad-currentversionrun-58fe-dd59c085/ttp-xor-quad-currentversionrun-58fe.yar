rule TTP_XOR_QUAD_CurrentVersionRun_58fe {
  strings:
    $key_58fe = { 0b 91 [2] 2f 9f [2] 04 b3 [2] 2a 91 [2] 3e 8a [2] 31 90 [2] 2f 8d [2] 2d 8c [2] 36 8a [2] 2a 8d [2] 36 a2 }

  condition:
    any of them
}