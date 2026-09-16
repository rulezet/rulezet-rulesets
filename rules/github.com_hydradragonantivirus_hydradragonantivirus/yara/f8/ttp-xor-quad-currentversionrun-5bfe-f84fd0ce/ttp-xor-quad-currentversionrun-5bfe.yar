rule TTP_XOR_QUAD_CurrentVersionRun_5bfe {
  strings:
    $key_5bfe = { 08 91 [2] 2c 9f [2] 07 b3 [2] 29 91 [2] 3d 8a [2] 32 90 [2] 2c 8d [2] 2e 8c [2] 35 8a [2] 29 8d [2] 35 a2 }

  condition:
    any of them
}