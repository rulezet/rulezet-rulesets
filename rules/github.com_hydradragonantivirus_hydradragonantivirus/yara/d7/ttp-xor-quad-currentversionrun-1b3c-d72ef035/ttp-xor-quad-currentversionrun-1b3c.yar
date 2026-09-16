rule TTP_XOR_QUAD_CurrentVersionRun_1b3c {
  strings:
    $key_1b3c = { 48 53 [2] 6c 5d [2] 47 71 [2] 69 53 [2] 7d 48 [2] 72 52 [2] 6c 4f [2] 6e 4e [2] 75 48 [2] 69 4f [2] 75 60 }

  condition:
    any of them
}