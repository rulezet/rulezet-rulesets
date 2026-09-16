rule TTP_XOR_QUAD_CurrentVersionRun_e4fc {
  strings:
    $key_e4fc = { b7 93 [2] 93 9d [2] b8 b1 [2] 96 93 [2] 82 88 [2] 8d 92 [2] 93 8f [2] 91 8e [2] 8a 88 [2] 96 8f [2] 8a a0 }

  condition:
    any of them
}