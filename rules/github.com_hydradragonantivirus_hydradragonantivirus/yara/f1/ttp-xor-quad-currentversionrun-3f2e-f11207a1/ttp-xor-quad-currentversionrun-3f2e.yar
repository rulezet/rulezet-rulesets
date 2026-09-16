rule TTP_XOR_QUAD_CurrentVersionRun_3f2e {
  strings:
    $key_3f2e = { 6c 41 [2] 48 4f [2] 63 63 [2] 4d 41 [2] 59 5a [2] 56 40 [2] 48 5d [2] 4a 5c [2] 51 5a [2] 4d 5d [2] 51 72 }

  condition:
    any of them
}