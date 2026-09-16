rule TTP_XOR_QUAD_CurrentVersionRun_12cb {
  strings:
    $key_12cb = { 41 a4 [2] 65 aa [2] 4e 86 [2] 60 a4 [2] 74 bf [2] 7b a5 [2] 65 b8 [2] 67 b9 [2] 7c bf [2] 60 b8 [2] 7c 97 }

  condition:
    any of them
}