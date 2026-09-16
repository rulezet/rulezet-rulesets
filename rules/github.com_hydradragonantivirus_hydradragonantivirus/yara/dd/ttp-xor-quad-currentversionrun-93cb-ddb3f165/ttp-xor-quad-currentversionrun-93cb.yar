rule TTP_XOR_QUAD_CurrentVersionRun_93cb {
  strings:
    $key_93cb = { c0 a4 [2] e4 aa [2] cf 86 [2] e1 a4 [2] f5 bf [2] fa a5 [2] e4 b8 [2] e6 b9 [2] fd bf [2] e1 b8 [2] fd 97 }

  condition:
    any of them
}