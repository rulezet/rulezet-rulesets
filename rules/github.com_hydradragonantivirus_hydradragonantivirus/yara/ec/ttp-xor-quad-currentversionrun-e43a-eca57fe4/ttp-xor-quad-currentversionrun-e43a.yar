rule TTP_XOR_QUAD_CurrentVersionRun_e43a {
  strings:
    $key_e43a = { b7 55 [2] 93 5b [2] b8 77 [2] 96 55 [2] 82 4e [2] 8d 54 [2] 93 49 [2] 91 48 [2] 8a 4e [2] 96 49 [2] 8a 66 }

  condition:
    any of them
}