rule TTP_XOR_QUAD_CurrentVersionRun_57fe {
  strings:
    $key_57fe = { 04 91 [2] 20 9f [2] 0b b3 [2] 25 91 [2] 31 8a [2] 3e 90 [2] 20 8d [2] 22 8c [2] 39 8a [2] 25 8d [2] 39 a2 }

  condition:
    any of them
}