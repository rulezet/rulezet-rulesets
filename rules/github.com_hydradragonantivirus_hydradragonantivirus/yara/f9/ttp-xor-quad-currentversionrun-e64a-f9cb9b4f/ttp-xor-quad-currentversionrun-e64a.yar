rule TTP_XOR_QUAD_CurrentVersionRun_e64a {
  strings:
    $key_e64a = { b5 25 [2] 91 2b [2] ba 07 [2] 94 25 [2] 80 3e [2] 8f 24 [2] 91 39 [2] 93 38 [2] 88 3e [2] 94 39 [2] 88 16 }

  condition:
    any of them
}