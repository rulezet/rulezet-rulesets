rule TTP_XOR_QUAD_CurrentVersionRun_a0cb {
  strings:
    $key_a0cb = { f3 a4 [2] d7 aa [2] fc 86 [2] d2 a4 [2] c6 bf [2] c9 a5 [2] d7 b8 [2] d5 b9 [2] ce bf [2] d2 b8 [2] ce 97 }

  condition:
    any of them
}