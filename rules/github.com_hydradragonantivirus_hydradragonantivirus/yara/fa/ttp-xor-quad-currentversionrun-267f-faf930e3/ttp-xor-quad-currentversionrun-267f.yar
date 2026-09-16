rule TTP_XOR_QUAD_CurrentVersionRun_267f {
  strings:
    $key_267f = { 75 10 [2] 51 1e [2] 7a 32 [2] 54 10 [2] 40 0b [2] 4f 11 [2] 51 0c [2] 53 0d [2] 48 0b [2] 54 0c [2] 48 23 }

  condition:
    any of them
}