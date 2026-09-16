rule TTP_XOR_QUAD_CurrentVersionRun_06cb {
  strings:
    $key_06cb = { 55 a4 [2] 71 aa [2] 5a 86 [2] 74 a4 [2] 60 bf [2] 6f a5 [2] 71 b8 [2] 73 b9 [2] 68 bf [2] 74 b8 [2] 68 97 }

  condition:
    any of them
}