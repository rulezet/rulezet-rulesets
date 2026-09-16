rule TTP_XOR_QUAD_CurrentVersionRun_46cb {
  strings:
    $key_46cb = { 15 a4 [2] 31 aa [2] 1a 86 [2] 34 a4 [2] 20 bf [2] 2f a5 [2] 31 b8 [2] 33 b9 [2] 28 bf [2] 34 b8 [2] 28 97 }

  condition:
    any of them
}