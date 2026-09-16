rule TTP_XOR_QUAD_CurrentVersionRun_3c4f {
  strings:
    $key_3c4f = { 6f 20 [2] 4b 2e [2] 60 02 [2] 4e 20 [2] 5a 3b [2] 55 21 [2] 4b 3c [2] 49 3d [2] 52 3b [2] 4e 3c [2] 52 13 }

  condition:
    any of them
}