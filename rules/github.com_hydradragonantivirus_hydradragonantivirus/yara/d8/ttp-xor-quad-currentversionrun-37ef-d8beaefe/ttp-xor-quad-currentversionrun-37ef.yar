rule TTP_XOR_QUAD_CurrentVersionRun_37ef {
  strings:
    $key_37ef = { 64 80 [2] 40 8e [2] 6b a2 [2] 45 80 [2] 51 9b [2] 5e 81 [2] 40 9c [2] 42 9d [2] 59 9b [2] 45 9c [2] 59 b3 }

  condition:
    any of them
}