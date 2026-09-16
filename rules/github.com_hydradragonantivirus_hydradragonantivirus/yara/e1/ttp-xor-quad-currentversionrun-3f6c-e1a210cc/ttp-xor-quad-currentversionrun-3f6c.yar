rule TTP_XOR_QUAD_CurrentVersionRun_3f6c {
  strings:
    $key_3f6c = { 6c 03 [2] 48 0d [2] 63 21 [2] 4d 03 [2] 59 18 [2] 56 02 [2] 48 1f [2] 4a 1e [2] 51 18 [2] 4d 1f [2] 51 30 }

  condition:
    any of them
}