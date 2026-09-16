rule TTP_XOR_QUAD_CurrentVersionRun_307e {
  strings:
    $key_307e = { 63 11 [2] 47 1f [2] 6c 33 [2] 42 11 [2] 56 0a [2] 59 10 [2] 47 0d [2] 45 0c [2] 5e 0a [2] 42 0d [2] 5e 22 }

  condition:
    any of them
}