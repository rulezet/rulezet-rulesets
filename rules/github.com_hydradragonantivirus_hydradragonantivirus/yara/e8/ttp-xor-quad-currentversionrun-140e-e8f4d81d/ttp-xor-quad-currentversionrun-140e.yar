rule TTP_XOR_QUAD_CurrentVersionRun_140e {
  strings:
    $key_140e = { 47 61 [2] 63 6f [2] 48 43 [2] 66 61 [2] 72 7a [2] 7d 60 [2] 63 7d [2] 61 7c [2] 7a 7a [2] 66 7d [2] 7a 52 }

  condition:
    any of them
}