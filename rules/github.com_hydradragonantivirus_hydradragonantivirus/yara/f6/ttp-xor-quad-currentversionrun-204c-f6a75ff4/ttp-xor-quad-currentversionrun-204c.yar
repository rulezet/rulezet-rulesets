rule TTP_XOR_QUAD_CurrentVersionRun_204c {
  strings:
    $key_204c = { 73 23 [2] 57 2d [2] 7c 01 [2] 52 23 [2] 46 38 [2] 49 22 [2] 57 3f [2] 55 3e [2] 4e 38 [2] 52 3f [2] 4e 10 }

  condition:
    any of them
}