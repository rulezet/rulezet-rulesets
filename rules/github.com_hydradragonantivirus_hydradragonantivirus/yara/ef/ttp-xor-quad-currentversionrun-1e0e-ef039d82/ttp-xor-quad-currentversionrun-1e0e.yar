rule TTP_XOR_QUAD_CurrentVersionRun_1e0e {
  strings:
    $key_1e0e = { 4d 61 [2] 69 6f [2] 42 43 [2] 6c 61 [2] 78 7a [2] 77 60 [2] 69 7d [2] 6b 7c [2] 70 7a [2] 6c 7d [2] 70 52 }

  condition:
    any of them
}