rule TTP_XOR_QUAD_CurrentVersionRun_95cb {
  strings:
    $key_95cb = { c6 a4 [2] e2 aa [2] c9 86 [2] e7 a4 [2] f3 bf [2] fc a5 [2] e2 b8 [2] e0 b9 [2] fb bf [2] e7 b8 [2] fb 97 }

  condition:
    any of them
}