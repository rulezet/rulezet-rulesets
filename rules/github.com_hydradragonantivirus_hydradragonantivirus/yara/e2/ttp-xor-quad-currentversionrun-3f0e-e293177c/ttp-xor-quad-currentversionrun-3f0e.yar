rule TTP_XOR_QUAD_CurrentVersionRun_3f0e {
  strings:
    $key_3f0e = { 6c 61 [2] 48 6f [2] 63 43 [2] 4d 61 [2] 59 7a [2] 56 60 [2] 48 7d [2] 4a 7c [2] 51 7a [2] 4d 7d [2] 51 52 }

  condition:
    any of them
}