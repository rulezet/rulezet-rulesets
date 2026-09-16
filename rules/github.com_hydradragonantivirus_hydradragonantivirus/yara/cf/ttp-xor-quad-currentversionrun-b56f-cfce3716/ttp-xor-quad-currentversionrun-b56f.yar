rule TTP_XOR_QUAD_CurrentVersionRun_b56f {
  strings:
    $key_b56f = { e6 00 [2] c2 0e [2] e9 22 [2] c7 00 [2] d3 1b [2] dc 01 [2] c2 1c [2] c0 1d [2] db 1b [2] c7 1c [2] db 33 }

  condition:
    any of them
}