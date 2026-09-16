rule TTP_XOR_QUAD_CurrentVersionRun_8dcb {
  strings:
    $key_8dcb = { de a4 [2] fa aa [2] d1 86 [2] ff a4 [2] eb bf [2] e4 a5 [2] fa b8 [2] f8 b9 [2] e3 bf [2] ff b8 [2] e3 97 }

  condition:
    any of them
}