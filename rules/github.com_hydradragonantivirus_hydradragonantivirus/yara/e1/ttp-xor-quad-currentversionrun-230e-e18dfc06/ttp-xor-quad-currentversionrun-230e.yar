rule TTP_XOR_QUAD_CurrentVersionRun_230e {
  strings:
    $key_230e = { 70 61 [2] 54 6f [2] 7f 43 [2] 51 61 [2] 45 7a [2] 4a 60 [2] 54 7d [2] 56 7c [2] 4d 7a [2] 51 7d [2] 4d 52 }

  condition:
    any of them
}