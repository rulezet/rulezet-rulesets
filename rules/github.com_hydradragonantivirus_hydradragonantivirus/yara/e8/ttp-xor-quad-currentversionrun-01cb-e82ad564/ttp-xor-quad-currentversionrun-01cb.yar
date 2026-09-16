rule TTP_XOR_QUAD_CurrentVersionRun_01cb {
  strings:
    $key_01cb = { 52 a4 [2] 76 aa [2] 5d 86 [2] 73 a4 [2] 67 bf [2] 68 a5 [2] 76 b8 [2] 74 b9 [2] 6f bf [2] 73 b8 [2] 6f 97 }

  condition:
    any of them
}