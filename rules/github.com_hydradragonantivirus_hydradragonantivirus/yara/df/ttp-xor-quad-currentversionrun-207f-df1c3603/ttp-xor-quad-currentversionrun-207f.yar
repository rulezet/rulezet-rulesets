rule TTP_XOR_QUAD_CurrentVersionRun_207f {
  strings:
    $key_207f = { 73 10 [2] 57 1e [2] 7c 32 [2] 52 10 [2] 46 0b [2] 49 11 [2] 57 0c [2] 55 0d [2] 4e 0b [2] 52 0c [2] 4e 23 }

  condition:
    any of them
}