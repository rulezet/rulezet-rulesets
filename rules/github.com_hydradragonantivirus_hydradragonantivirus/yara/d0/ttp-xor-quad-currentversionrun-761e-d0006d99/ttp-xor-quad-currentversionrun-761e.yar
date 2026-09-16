rule TTP_XOR_QUAD_CurrentVersionRun_761e {
  strings:
    $key_761e = { 25 71 [2] 01 7f [2] 2a 53 [2] 04 71 [2] 10 6a [2] 1f 70 [2] 01 6d [2] 03 6c [2] 18 6a [2] 04 6d [2] 18 42 }

  condition:
    any of them
}