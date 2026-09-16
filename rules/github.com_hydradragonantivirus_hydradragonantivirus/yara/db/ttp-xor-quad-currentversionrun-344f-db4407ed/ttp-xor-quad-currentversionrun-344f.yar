rule TTP_XOR_QUAD_CurrentVersionRun_344f {
  strings:
    $key_344f = { 67 20 [2] 43 2e [2] 68 02 [2] 46 20 [2] 52 3b [2] 5d 21 [2] 43 3c [2] 41 3d [2] 5a 3b [2] 46 3c [2] 5a 13 }

  condition:
    any of them
}