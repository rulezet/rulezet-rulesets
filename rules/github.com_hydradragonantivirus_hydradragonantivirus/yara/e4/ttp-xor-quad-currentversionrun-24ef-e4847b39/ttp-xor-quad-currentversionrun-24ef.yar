rule TTP_XOR_QUAD_CurrentVersionRun_24ef {
  strings:
    $key_24ef = { 77 80 [2] 53 8e [2] 78 a2 [2] 56 80 [2] 42 9b [2] 4d 81 [2] 53 9c [2] 51 9d [2] 4a 9b [2] 56 9c [2] 4a b3 }

  condition:
    any of them
}