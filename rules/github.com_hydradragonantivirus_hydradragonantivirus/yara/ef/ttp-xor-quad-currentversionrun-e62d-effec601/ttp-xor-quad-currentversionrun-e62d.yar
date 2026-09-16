rule TTP_XOR_QUAD_CurrentVersionRun_e62d {
  strings:
    $key_e62d = { b5 42 [2] 91 4c [2] ba 60 [2] 94 42 [2] 80 59 [2] 8f 43 [2] 91 5e [2] 93 5f [2] 88 59 [2] 94 5e [2] 88 71 }

  condition:
    any of them
}