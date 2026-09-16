rule TTP_XOR_QUAD_CurrentVersionRun_210e {
  strings:
    $key_210e = { 72 61 [2] 56 6f [2] 7d 43 [2] 53 61 [2] 47 7a [2] 48 60 [2] 56 7d [2] 54 7c [2] 4f 7a [2] 53 7d [2] 4f 52 }

  condition:
    any of them
}