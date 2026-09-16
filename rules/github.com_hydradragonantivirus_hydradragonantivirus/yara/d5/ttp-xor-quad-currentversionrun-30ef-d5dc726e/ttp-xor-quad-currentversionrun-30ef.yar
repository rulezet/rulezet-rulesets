rule TTP_XOR_QUAD_CurrentVersionRun_30ef {
  strings:
    $key_30ef = { 63 80 [2] 47 8e [2] 6c a2 [2] 42 80 [2] 56 9b [2] 59 81 [2] 47 9c [2] 45 9d [2] 5e 9b [2] 42 9c [2] 5e b3 }

  condition:
    any of them
}