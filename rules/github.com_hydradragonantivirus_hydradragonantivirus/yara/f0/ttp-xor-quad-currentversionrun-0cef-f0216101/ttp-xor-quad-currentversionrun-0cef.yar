rule TTP_XOR_QUAD_CurrentVersionRun_0cef {
  strings:
    $key_0cef = { 5f 80 [2] 7b 8e [2] 50 a2 [2] 7e 80 [2] 6a 9b [2] 65 81 [2] 7b 9c [2] 79 9d [2] 62 9b [2] 7e 9c [2] 62 b3 }

  condition:
    any of them
}