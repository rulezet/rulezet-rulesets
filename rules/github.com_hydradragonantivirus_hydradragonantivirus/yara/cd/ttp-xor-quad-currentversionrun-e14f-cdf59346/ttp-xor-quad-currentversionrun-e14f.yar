rule TTP_XOR_QUAD_CurrentVersionRun_e14f {
  strings:
    $key_e14f = { b2 20 [2] 96 2e [2] bd 02 [2] 93 20 [2] 87 3b [2] 88 21 [2] 96 3c [2] 94 3d [2] 8f 3b [2] 93 3c [2] 8f 13 }

  condition:
    any of them
}