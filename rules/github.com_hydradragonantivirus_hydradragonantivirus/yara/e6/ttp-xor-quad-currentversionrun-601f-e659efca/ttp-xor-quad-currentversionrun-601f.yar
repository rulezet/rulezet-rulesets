rule TTP_XOR_QUAD_CurrentVersionRun_601f {
  strings:
    $key_601f = { 33 70 [2] 17 7e [2] 3c 52 [2] 12 70 [2] 06 6b [2] 09 71 [2] 17 6c [2] 15 6d [2] 0e 6b [2] 12 6c [2] 0e 43 }

  condition:
    any of them
}