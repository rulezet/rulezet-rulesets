rule TTP_XOR_QUAD_CurrentVersionRun_8a34 {
  strings:
    $key_8a34 = { d9 5b [2] fd 55 [2] d6 79 [2] f8 5b [2] ec 40 [2] e3 5a [2] fd 47 [2] ff 46 [2] e4 40 [2] f8 47 [2] e4 68 }

  condition:
    any of them
}