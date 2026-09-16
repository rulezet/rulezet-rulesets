rule TTP_XOR_QUAD_CurrentVersionRun_0b3c {
  strings:
    $key_0b3c = { 58 53 [2] 7c 5d [2] 57 71 [2] 79 53 [2] 6d 48 [2] 62 52 [2] 7c 4f [2] 7e 4e [2] 65 48 [2] 79 4f [2] 65 60 }

  condition:
    any of them
}