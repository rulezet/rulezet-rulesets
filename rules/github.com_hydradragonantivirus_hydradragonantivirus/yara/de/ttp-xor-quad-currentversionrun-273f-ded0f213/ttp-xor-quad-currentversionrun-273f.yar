rule TTP_XOR_QUAD_CurrentVersionRun_273f {
  strings:
    $key_273f = { 74 50 [2] 50 5e [2] 7b 72 [2] 55 50 [2] 41 4b [2] 4e 51 [2] 50 4c [2] 52 4d [2] 49 4b [2] 55 4c [2] 49 63 }

  condition:
    any of them
}