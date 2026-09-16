rule TTP_XOR_QUAD_CurrentVersionRun_83cb {
  strings:
    $key_83cb = { d0 a4 [2] f4 aa [2] df 86 [2] f1 a4 [2] e5 bf [2] ea a5 [2] f4 b8 [2] f6 b9 [2] ed bf [2] f1 b8 [2] ed 97 }

  condition:
    any of them
}