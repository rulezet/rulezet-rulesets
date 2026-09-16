rule TTP_XOR_QUAD_CurrentVersionRun_211e {
  strings:
    $key_211e = { 72 71 [2] 56 7f [2] 7d 53 [2] 53 71 [2] 47 6a [2] 48 70 [2] 56 6d [2] 54 6c [2] 4f 6a [2] 53 6d [2] 4f 42 }

  condition:
    any of them
}