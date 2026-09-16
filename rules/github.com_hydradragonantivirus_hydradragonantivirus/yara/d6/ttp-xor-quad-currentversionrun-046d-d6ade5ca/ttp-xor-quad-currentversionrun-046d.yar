rule TTP_XOR_QUAD_CurrentVersionRun_046d {
  strings:
    $key_046d = { 57 02 [2] 73 0c [2] 58 20 [2] 76 02 [2] 62 19 [2] 6d 03 [2] 73 1e [2] 71 1f [2] 6a 19 [2] 76 1e [2] 6a 31 }

  condition:
    any of them
}