rule TTP_XOR_QUAD_CurrentVersionRun_e1fc {
  strings:
    $key_e1fc = { b2 93 [2] 96 9d [2] bd b1 [2] 93 93 [2] 87 88 [2] 88 92 [2] 96 8f [2] 94 8e [2] 8f 88 [2] 93 8f [2] 8f a0 }

  condition:
    any of them
}