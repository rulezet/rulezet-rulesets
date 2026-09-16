rule TTP_XOR_QUAD_CurrentVersionRun_174f {
  strings:
    $key_174f = { 44 20 [2] 60 2e [2] 4b 02 [2] 65 20 [2] 71 3b [2] 7e 21 [2] 60 3c [2] 62 3d [2] 79 3b [2] 65 3c [2] 79 13 }

  condition:
    any of them
}