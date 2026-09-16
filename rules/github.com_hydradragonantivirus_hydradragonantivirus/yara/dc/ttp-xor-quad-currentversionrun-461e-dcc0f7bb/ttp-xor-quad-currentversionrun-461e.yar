rule TTP_XOR_QUAD_CurrentVersionRun_461e {
  strings:
    $key_461e = { 15 71 [2] 31 7f [2] 1a 53 [2] 34 71 [2] 20 6a [2] 2f 70 [2] 31 6d [2] 33 6c [2] 28 6a [2] 34 6d [2] 28 42 }

  condition:
    any of them
}