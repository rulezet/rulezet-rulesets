rule TTP_XOR_QUAD_CurrentVersionRun_2e1e {
  strings:
    $key_2e1e = { 7d 71 [2] 59 7f [2] 72 53 [2] 5c 71 [2] 48 6a [2] 47 70 [2] 59 6d [2] 5b 6c [2] 40 6a [2] 5c 6d [2] 40 42 }

  condition:
    any of them
}