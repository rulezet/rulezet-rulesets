rule TTP_XOR_QUAD_CurrentVersionRun_8acb {
  strings:
    $key_8acb = { d9 a4 [2] fd aa [2] d6 86 [2] f8 a4 [2] ec bf [2] e3 a5 [2] fd b8 [2] ff b9 [2] e4 bf [2] f8 b8 [2] e4 97 }

  condition:
    any of them
}