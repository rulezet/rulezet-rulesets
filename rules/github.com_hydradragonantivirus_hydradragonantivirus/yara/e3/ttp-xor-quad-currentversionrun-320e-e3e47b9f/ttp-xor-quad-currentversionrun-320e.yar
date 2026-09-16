rule TTP_XOR_QUAD_CurrentVersionRun_320e {
  strings:
    $key_320e = { 61 61 [2] 45 6f [2] 6e 43 [2] 40 61 [2] 54 7a [2] 5b 60 [2] 45 7d [2] 47 7c [2] 5c 7a [2] 40 7d [2] 5c 52 }

  condition:
    any of them
}