rule TTP_XOR_QUAD_CurrentVersionRun_e60f {
  strings:
    $key_e60f = { b5 60 [2] 91 6e [2] ba 42 [2] 94 60 [2] 80 7b [2] 8f 61 [2] 91 7c [2] 93 7d [2] 88 7b [2] 94 7c [2] 88 53 }

  condition:
    any of them
}