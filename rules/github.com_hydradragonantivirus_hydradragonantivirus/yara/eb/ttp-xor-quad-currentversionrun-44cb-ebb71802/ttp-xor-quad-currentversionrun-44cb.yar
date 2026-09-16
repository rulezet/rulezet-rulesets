rule TTP_XOR_QUAD_CurrentVersionRun_44cb {
  strings:
    $key_44cb = { 17 a4 [2] 33 aa [2] 18 86 [2] 36 a4 [2] 22 bf [2] 2d a5 [2] 33 b8 [2] 31 b9 [2] 2a bf [2] 36 b8 [2] 2a 97 }

  condition:
    any of them
}