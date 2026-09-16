rule TTP_XOR_QUAD_CurrentVersionRun_f14f {
  strings:
    $key_f14f = { a2 20 [2] 86 2e [2] ad 02 [2] 83 20 [2] 97 3b [2] 98 21 [2] 86 3c [2] 84 3d [2] 9f 3b [2] 83 3c [2] 9f 13 }

  condition:
    any of them
}