rule TTP_XOR_QUAD_CurrentVersionRun_53cb {
  strings:
    $key_53cb = { 00 a4 [2] 24 aa [2] 0f 86 [2] 21 a4 [2] 35 bf [2] 3a a5 [2] 24 b8 [2] 26 b9 [2] 3d bf [2] 21 b8 [2] 3d 97 }

  condition:
    any of them
}