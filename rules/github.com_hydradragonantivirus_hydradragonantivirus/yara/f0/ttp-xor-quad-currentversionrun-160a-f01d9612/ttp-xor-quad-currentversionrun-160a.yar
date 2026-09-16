rule TTP_XOR_QUAD_CurrentVersionRun_160a {
  strings:
    $key_160a = { 45 65 [2] 61 6b [2] 4a 47 [2] 64 65 [2] 70 7e [2] 7f 64 [2] 61 79 [2] 63 78 [2] 78 7e [2] 64 79 [2] 78 56 }

  condition:
    any of them
}