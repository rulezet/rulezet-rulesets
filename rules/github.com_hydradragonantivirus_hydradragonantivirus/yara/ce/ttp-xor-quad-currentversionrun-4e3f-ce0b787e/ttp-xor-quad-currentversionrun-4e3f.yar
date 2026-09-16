rule TTP_XOR_QUAD_CurrentVersionRun_4e3f {
  strings:
    $key_4e3f = { 1d 50 [2] 39 5e [2] 12 72 [2] 3c 50 [2] 28 4b [2] 27 51 [2] 39 4c [2] 3b 4d [2] 20 4b [2] 3c 4c [2] 20 63 }

  condition:
    any of them
}