rule TTP_XOR_QUAD_CurrentVersionRun_22fe {
  strings:
    $key_22fe = { 71 91 [2] 55 9f [2] 7e b3 [2] 50 91 [2] 44 8a [2] 4b 90 [2] 55 8d [2] 57 8c [2] 4c 8a [2] 50 8d [2] 4c a2 }

  condition:
    any of them
}