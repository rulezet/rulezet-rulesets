rule TTP_XOR_QUAD_CurrentVersionRun_3e3c {
  strings:
    $key_3e3c = { 6d 53 [2] 49 5d [2] 62 71 [2] 4c 53 [2] 58 48 [2] 57 52 [2] 49 4f [2] 4b 4e [2] 50 48 [2] 4c 4f [2] 50 60 }

  condition:
    any of them
}