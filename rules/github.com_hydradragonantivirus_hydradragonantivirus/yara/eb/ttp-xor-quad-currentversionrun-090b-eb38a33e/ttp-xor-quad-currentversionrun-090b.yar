rule TTP_XOR_QUAD_CurrentVersionRun_090b {
  strings:
    $key_090b = { 5a 64 [2] 7e 6a [2] 55 46 [2] 7b 64 [2] 6f 7f [2] 60 65 [2] 7e 78 [2] 7c 79 [2] 67 7f [2] 7b 78 [2] 67 57 }

  condition:
    any of them
}