rule TTP_XOR_QUAD_CurrentVersionRun_b55f {
  strings:
    $key_b55f = { e6 30 [2] c2 3e [2] e9 12 [2] c7 30 [2] d3 2b [2] dc 31 [2] c2 2c [2] c0 2d [2] db 2b [2] c7 2c [2] db 03 }

  condition:
    any of them
}