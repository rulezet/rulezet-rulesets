rule TTP_XOR_QUAD_CurrentVersionRun_17f0 {
  strings:
    $key_17f0 = { 44 9f [2] 60 91 [2] 4b bd [2] 65 9f [2] 71 84 [2] 7e 9e [2] 60 83 [2] 62 82 [2] 79 84 [2] 65 83 [2] 79 ac }

  condition:
    any of them
}