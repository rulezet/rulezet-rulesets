rule TTP_XOR_QUAD_CurrentVersionRun_161e {
  strings:
    $key_161e = { 45 71 [2] 61 7f [2] 4a 53 [2] 64 71 [2] 70 6a [2] 7f 70 [2] 61 6d [2] 63 6c [2] 78 6a [2] 64 6d [2] 78 42 }

  condition:
    any of them
}