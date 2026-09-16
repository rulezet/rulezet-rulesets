rule TTP_XOR_QUAD_CurrentVersionRun_620e {
  strings:
    $key_620e = { 31 61 [2] 15 6f [2] 3e 43 [2] 10 61 [2] 04 7a [2] 0b 60 [2] 15 7d [2] 17 7c [2] 0c 7a [2] 10 7d [2] 0c 52 }

  condition:
    any of them
}