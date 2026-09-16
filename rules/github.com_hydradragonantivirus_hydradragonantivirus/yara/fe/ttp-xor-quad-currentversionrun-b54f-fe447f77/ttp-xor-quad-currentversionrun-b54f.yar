rule TTP_XOR_QUAD_CurrentVersionRun_b54f {
  strings:
    $key_b54f = { e6 20 [2] c2 2e [2] e9 02 [2] c7 20 [2] d3 3b [2] dc 21 [2] c2 3c [2] c0 3d [2] db 3b [2] c7 3c [2] db 13 }

  condition:
    any of them
}