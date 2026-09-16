rule TTP_XOR_QUAD_CurrentVersionRun_577e {
  strings:
    $key_577e = { 04 11 [2] 20 1f [2] 0b 33 [2] 25 11 [2] 31 0a [2] 3e 10 [2] 20 0d [2] 22 0c [2] 39 0a [2] 25 0d [2] 39 22 }

  condition:
    any of them
}