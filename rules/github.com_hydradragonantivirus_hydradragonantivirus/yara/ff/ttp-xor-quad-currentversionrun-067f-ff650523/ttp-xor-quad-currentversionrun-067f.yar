rule TTP_XOR_QUAD_CurrentVersionRun_067f {
  strings:
    $key_067f = { 55 10 [2] 71 1e [2] 5a 32 [2] 74 10 [2] 60 0b [2] 6f 11 [2] 71 0c [2] 73 0d [2] 68 0b [2] 74 0c [2] 68 23 }

  condition:
    any of them
}