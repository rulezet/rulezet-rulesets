rule TTP_XOR_QUAD_CurrentVersionRun_e42f {
  strings:
    $key_e42f = { b7 40 [2] 93 4e [2] b8 62 [2] 96 40 [2] 82 5b [2] 8d 41 [2] 93 5c [2] 91 5d [2] 8a 5b [2] 96 5c [2] 8a 73 }

  condition:
    any of them
}