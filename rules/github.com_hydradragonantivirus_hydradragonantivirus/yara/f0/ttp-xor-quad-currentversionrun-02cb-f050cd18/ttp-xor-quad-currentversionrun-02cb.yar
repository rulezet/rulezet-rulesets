rule TTP_XOR_QUAD_CurrentVersionRun_02cb {
  strings:
    $key_02cb = { 51 a4 [2] 75 aa [2] 5e 86 [2] 70 a4 [2] 64 bf [2] 6b a5 [2] 75 b8 [2] 77 b9 [2] 6c bf [2] 70 b8 [2] 6c 97 }

  condition:
    any of them
}