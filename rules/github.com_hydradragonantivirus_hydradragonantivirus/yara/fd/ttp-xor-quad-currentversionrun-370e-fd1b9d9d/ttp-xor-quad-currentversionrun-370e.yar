rule TTP_XOR_QUAD_CurrentVersionRun_370e {
  strings:
    $key_370e = { 64 61 [2] 40 6f [2] 6b 43 [2] 45 61 [2] 51 7a [2] 5e 60 [2] 40 7d [2] 42 7c [2] 59 7a [2] 45 7d [2] 59 52 }

  condition:
    any of them
}