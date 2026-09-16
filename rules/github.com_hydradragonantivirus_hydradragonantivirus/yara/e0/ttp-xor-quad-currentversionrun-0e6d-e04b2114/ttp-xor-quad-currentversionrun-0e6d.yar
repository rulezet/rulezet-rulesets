rule TTP_XOR_QUAD_CurrentVersionRun_0e6d {
  strings:
    $key_0e6d = { 5d 02 [2] 79 0c [2] 52 20 [2] 7c 02 [2] 68 19 [2] 67 03 [2] 79 1e [2] 7b 1f [2] 60 19 [2] 7c 1e [2] 60 31 }

  condition:
    any of them
}