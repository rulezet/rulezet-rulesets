rule TTP_XOR_QUAD_CurrentVersionRun_85cb {
  strings:
    $key_85cb = { d6 a4 [2] f2 aa [2] d9 86 [2] f7 a4 [2] e3 bf [2] ec a5 [2] f2 b8 [2] f0 b9 [2] eb bf [2] f7 b8 [2] eb 97 }

  condition:
    any of them
}