rule TTP_XOR_QUAD_CurrentVersionRun_e66d {
  strings:
    $key_e66d = { b5 02 [2] 91 0c [2] ba 20 [2] 94 02 [2] 80 19 [2] 8f 03 [2] 91 1e [2] 93 1f [2] 88 19 [2] 94 1e [2] 88 31 }

  condition:
    any of them
}