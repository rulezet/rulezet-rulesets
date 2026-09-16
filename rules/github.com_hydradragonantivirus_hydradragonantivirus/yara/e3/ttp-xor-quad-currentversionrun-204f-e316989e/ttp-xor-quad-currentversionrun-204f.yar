rule TTP_XOR_QUAD_CurrentVersionRun_204f {
  strings:
    $key_204f = { 73 20 [2] 57 2e [2] 7c 02 [2] 52 20 [2] 46 3b [2] 49 21 [2] 57 3c [2] 55 3d [2] 4e 3b [2] 52 3c [2] 4e 13 }

  condition:
    any of them
}