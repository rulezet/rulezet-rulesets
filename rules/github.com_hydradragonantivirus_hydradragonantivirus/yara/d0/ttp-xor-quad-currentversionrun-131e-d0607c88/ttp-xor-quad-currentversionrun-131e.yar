rule TTP_XOR_QUAD_CurrentVersionRun_131e {
  strings:
    $key_131e = { 40 71 [2] 64 7f [2] 4f 53 [2] 61 71 [2] 75 6a [2] 7a 70 [2] 64 6d [2] 66 6c [2] 7d 6a [2] 61 6d [2] 7d 42 }

  condition:
    any of them
}