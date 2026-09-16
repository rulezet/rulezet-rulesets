rule TTP_XOR_QUAD_CurrentVersionRun_643c {
  strings:
    $key_643c = { 37 53 [2] 13 5d [2] 38 71 [2] 16 53 [2] 02 48 [2] 0d 52 [2] 13 4f [2] 11 4e [2] 0a 48 [2] 16 4f [2] 0a 60 }

  condition:
    any of them
}