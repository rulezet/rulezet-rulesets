rule TTP_XOR_QUAD_CurrentVersionRun_8aa3 {
  strings:
    $key_8aa3 = { d9 cc [2] fd c2 [2] d6 ee [2] f8 cc [2] ec d7 [2] e3 cd [2] fd d0 [2] ff d1 [2] e4 d7 [2] f8 d0 [2] e4 ff }

  condition:
    any of them
}