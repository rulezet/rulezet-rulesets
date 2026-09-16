rule TTP_XOR_QUAD_CurrentVersionRun_0c3f {
  strings:
    $key_0c3f = { 5f 50 [2] 7b 5e [2] 50 72 [2] 7e 50 [2] 6a 4b [2] 65 51 [2] 7b 4c [2] 79 4d [2] 62 4b [2] 7e 4c [2] 62 63 }

  condition:
    any of them
}