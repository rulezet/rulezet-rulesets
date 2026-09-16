rule TTP_XOR_QUAD_CurrentVersionRun_3d0e {
  strings:
    $key_3d0e = { 6e 61 [2] 4a 6f [2] 61 43 [2] 4f 61 [2] 5b 7a [2] 54 60 [2] 4a 7d [2] 48 7c [2] 53 7a [2] 4f 7d [2] 53 52 }

  condition:
    any of them
}