rule TTP_XOR_QUAD_CurrentVersionRun_24cb {
  strings:
    $key_24cb = { 77 a4 [2] 53 aa [2] 78 86 [2] 56 a4 [2] 42 bf [2] 4d a5 [2] 53 b8 [2] 51 b9 [2] 4a bf [2] 56 b8 [2] 4a 97 }

  condition:
    any of them
}