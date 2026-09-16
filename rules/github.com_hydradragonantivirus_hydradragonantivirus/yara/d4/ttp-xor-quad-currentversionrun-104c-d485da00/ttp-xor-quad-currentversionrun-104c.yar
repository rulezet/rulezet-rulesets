rule TTP_XOR_QUAD_CurrentVersionRun_104c {
  strings:
    $key_104c = { 43 23 [2] 67 2d [2] 4c 01 [2] 62 23 [2] 76 38 [2] 79 22 [2] 67 3f [2] 65 3e [2] 7e 38 [2] 62 3f [2] 7e 10 }

  condition:
    any of them
}