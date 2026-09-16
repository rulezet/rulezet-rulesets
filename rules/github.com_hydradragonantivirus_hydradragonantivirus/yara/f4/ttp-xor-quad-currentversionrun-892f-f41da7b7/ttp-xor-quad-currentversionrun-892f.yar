rule TTP_XOR_QUAD_CurrentVersionRun_892f {
  strings:
    $key_892f = { da 40 [2] fe 4e [2] d5 62 [2] fb 40 [2] ef 5b [2] e0 41 [2] fe 5c [2] fc 5d [2] e7 5b [2] fb 5c [2] e7 73 }

  condition:
    any of them
}