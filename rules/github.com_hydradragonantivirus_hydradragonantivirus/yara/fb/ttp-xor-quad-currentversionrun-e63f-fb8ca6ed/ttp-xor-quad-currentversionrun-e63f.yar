rule TTP_XOR_QUAD_CurrentVersionRun_e63f {
  strings:
    $key_e63f = { b5 50 [2] 91 5e [2] ba 72 [2] 94 50 [2] 80 4b [2] 8f 51 [2] 91 4c [2] 93 4d [2] 88 4b [2] 94 4c [2] 88 63 }

  condition:
    any of them
}