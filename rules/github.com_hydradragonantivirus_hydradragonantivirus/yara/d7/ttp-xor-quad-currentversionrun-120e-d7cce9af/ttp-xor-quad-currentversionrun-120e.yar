rule TTP_XOR_QUAD_CurrentVersionRun_120e {
  strings:
    $key_120e = { 41 61 [2] 65 6f [2] 4e 43 [2] 60 61 [2] 74 7a [2] 7b 60 [2] 65 7d [2] 67 7c [2] 7c 7a [2] 60 7d [2] 7c 52 }

  condition:
    any of them
}