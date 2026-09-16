rule TTP_XOR_QUAD_CurrentVersionRun_234f {
  strings:
    $key_234f = { 70 20 [2] 54 2e [2] 7f 02 [2] 51 20 [2] 45 3b [2] 4a 21 [2] 54 3c [2] 56 3d [2] 4d 3b [2] 51 3c [2] 4d 13 }

  condition:
    any of them
}