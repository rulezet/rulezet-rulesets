rule TTP_XOR_QUAD_CurrentVersionRun_e50e {
  strings:
    $key_e50e = { b6 61 [2] 92 6f [2] b9 43 [2] 97 61 [2] 83 7a [2] 8c 60 [2] 92 7d [2] 90 7c [2] 8b 7a [2] 97 7d [2] 8b 52 }

  condition:
    any of them
}