rule TTP_XOR_QUAD_CurrentVersionRun_3f1e {
  strings:
    $key_3f1e = { 6c 71 [2] 48 7f [2] 63 53 [2] 4d 71 [2] 59 6a [2] 56 70 [2] 48 6d [2] 4a 6c [2] 51 6a [2] 4d 6d [2] 51 42 }

  condition:
    any of them
}