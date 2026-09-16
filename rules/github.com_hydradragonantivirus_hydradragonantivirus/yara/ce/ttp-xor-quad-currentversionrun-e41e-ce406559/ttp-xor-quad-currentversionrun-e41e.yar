rule TTP_XOR_QUAD_CurrentVersionRun_e41e {
  strings:
    $key_e41e = { b7 71 [2] 93 7f [2] b8 53 [2] 96 71 [2] 82 6a [2] 8d 70 [2] 93 6d [2] 91 6c [2] 8a 6a [2] 96 6d [2] 8a 42 }

  condition:
    any of them
}