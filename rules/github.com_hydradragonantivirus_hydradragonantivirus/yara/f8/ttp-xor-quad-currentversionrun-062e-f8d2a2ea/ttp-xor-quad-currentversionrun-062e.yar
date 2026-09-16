rule TTP_XOR_QUAD_CurrentVersionRun_062e {
  strings:
    $key_062e = { 55 41 [2] 71 4f [2] 5a 63 [2] 74 41 [2] 60 5a [2] 6f 40 [2] 71 5d [2] 73 5c [2] 68 5a [2] 74 5d [2] 68 72 }

  condition:
    any of them
}