rule TTP_XOR_QUAD_CurrentVersionRun_152a {
  strings:
    $key_152a = { 46 45 [2] 62 4b [2] 49 67 [2] 67 45 [2] 73 5e [2] 7c 44 [2] 62 59 [2] 60 58 [2] 7b 5e [2] 67 59 [2] 7b 76 }

  condition:
    any of them
}