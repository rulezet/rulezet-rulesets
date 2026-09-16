rule TTP_XOR_QUAD_CurrentVersionRun_62cb {
  strings:
    $key_62cb = { 31 a4 [2] 15 aa [2] 3e 86 [2] 10 a4 [2] 04 bf [2] 0b a5 [2] 15 b8 [2] 17 b9 [2] 0c bf [2] 10 b8 [2] 0c 97 }

  condition:
    any of them
}