rule TTP_XOR_QUAD_CurrentVersionRun_290a {
  strings:
    $key_290a = { 7a 65 [2] 5e 6b [2] 75 47 [2] 5b 65 [2] 4f 7e [2] 40 64 [2] 5e 79 [2] 5c 78 [2] 47 7e [2] 5b 79 [2] 47 56 }

  condition:
    any of them
}