rule TTP_XOR_QUAD_CurrentVersionRun_15ef {
  strings:
    $key_15ef = { 46 80 [2] 62 8e [2] 49 a2 [2] 67 80 [2] 73 9b [2] 7c 81 [2] 62 9c [2] 60 9d [2] 7b 9b [2] 67 9c [2] 7b b3 }

  condition:
    any of them
}