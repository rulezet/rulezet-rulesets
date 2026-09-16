rule TTP_XOR_QUAD_CurrentVersionRun_152e {
  strings:
    $key_152e = { 46 41 [2] 62 4f [2] 49 63 [2] 67 41 [2] 73 5a [2] 7c 40 [2] 62 5d [2] 60 5c [2] 7b 5a [2] 67 5d [2] 7b 72 }

  condition:
    any of them
}