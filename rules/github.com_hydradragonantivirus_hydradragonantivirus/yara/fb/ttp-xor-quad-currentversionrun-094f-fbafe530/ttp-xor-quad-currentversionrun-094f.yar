rule TTP_XOR_QUAD_CurrentVersionRun_094f {
  strings:
    $key_094f = { 5a 20 [2] 7e 2e [2] 55 02 [2] 7b 20 [2] 6f 3b [2] 60 21 [2] 7e 3c [2] 7c 3d [2] 67 3b [2] 7b 3c [2] 67 13 }

  condition:
    any of them
}