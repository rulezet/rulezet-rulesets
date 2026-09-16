rule TTP_XOR_QUAD_CurrentVersionRun_172c {
  strings:
    $key_172c = { 44 43 [2] 60 4d [2] 4b 61 [2] 65 43 [2] 71 58 [2] 7e 42 [2] 60 5f [2] 62 5e [2] 79 58 [2] 65 5f [2] 79 70 }

  condition:
    any of them
}