rule TTP_XOR_QUAD_CurrentVersionRun_157c {
  strings:
    $key_157c = { 46 13 [2] 62 1d [2] 49 31 [2] 67 13 [2] 73 08 [2] 7c 12 [2] 62 0f [2] 60 0e [2] 7b 08 [2] 67 0f [2] 7b 20 }

  condition:
    any of them
}