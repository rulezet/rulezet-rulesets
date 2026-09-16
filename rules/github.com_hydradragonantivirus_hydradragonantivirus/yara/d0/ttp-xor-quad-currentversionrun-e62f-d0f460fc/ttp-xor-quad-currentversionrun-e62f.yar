rule TTP_XOR_QUAD_CurrentVersionRun_e62f {
  strings:
    $key_e62f = { b5 40 [2] 91 4e [2] ba 62 [2] 94 40 [2] 80 5b [2] 8f 41 [2] 91 5c [2] 93 5d [2] 88 5b [2] 94 5c [2] 88 73 }

  condition:
    any of them
}