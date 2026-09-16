rule TTP_XOR_QUAD_CurrentVersionRun_6cef {
  strings:
    $key_6cef = { 3f 80 [2] 1b 8e [2] 30 a2 [2] 1e 80 [2] 0a 9b [2] 05 81 [2] 1b 9c [2] 19 9d [2] 02 9b [2] 1e 9c [2] 02 b3 }

  condition:
    any of them
}