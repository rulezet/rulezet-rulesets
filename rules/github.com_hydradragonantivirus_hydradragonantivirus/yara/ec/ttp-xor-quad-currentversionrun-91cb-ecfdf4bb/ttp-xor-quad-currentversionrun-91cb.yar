rule TTP_XOR_QUAD_CurrentVersionRun_91cb {
  strings:
    $key_91cb = { c2 a4 [2] e6 aa [2] cd 86 [2] e3 a4 [2] f7 bf [2] f8 a5 [2] e6 b8 [2] e4 b9 [2] ff bf [2] e3 b8 [2] ff 97 }

  condition:
    any of them
}