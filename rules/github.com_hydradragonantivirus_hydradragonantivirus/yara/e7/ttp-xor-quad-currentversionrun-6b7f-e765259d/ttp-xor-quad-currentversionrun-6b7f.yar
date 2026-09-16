rule TTP_XOR_QUAD_CurrentVersionRun_6b7f {
  strings:
    $key_6b7f = { 38 10 [2] 1c 1e [2] 37 32 [2] 19 10 [2] 0d 0b [2] 02 11 [2] 1c 0c [2] 1e 0d [2] 05 0b [2] 19 0c [2] 05 23 }

  condition:
    any of them
}