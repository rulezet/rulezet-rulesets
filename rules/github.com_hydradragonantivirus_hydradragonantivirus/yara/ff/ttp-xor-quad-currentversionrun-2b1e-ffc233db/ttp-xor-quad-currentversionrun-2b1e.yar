rule TTP_XOR_QUAD_CurrentVersionRun_2b1e {
  strings:
    $key_2b1e = { 78 71 [2] 5c 7f [2] 77 53 [2] 59 71 [2] 4d 6a [2] 42 70 [2] 5c 6d [2] 5e 6c [2] 45 6a [2] 59 6d [2] 45 42 }

  condition:
    any of them
}