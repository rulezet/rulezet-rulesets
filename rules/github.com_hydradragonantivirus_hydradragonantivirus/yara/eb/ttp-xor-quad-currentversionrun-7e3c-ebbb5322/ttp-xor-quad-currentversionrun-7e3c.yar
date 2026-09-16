rule TTP_XOR_QUAD_CurrentVersionRun_7e3c {
  strings:
    $key_7e3c = { 2d 53 [2] 09 5d [2] 22 71 [2] 0c 53 [2] 18 48 [2] 17 52 [2] 09 4f [2] 0b 4e [2] 10 48 [2] 0c 4f [2] 10 60 }

  condition:
    any of them
}