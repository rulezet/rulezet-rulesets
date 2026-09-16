rule TTP_XOR_QUAD_CurrentVersionRun_380a {
  strings:
    $key_380a = { 6b 65 [2] 4f 6b [2] 64 47 [2] 4a 65 [2] 5e 7e [2] 51 64 [2] 4f 79 [2] 4d 78 [2] 56 7e [2] 4a 79 [2] 56 56 }

  condition:
    any of them
}