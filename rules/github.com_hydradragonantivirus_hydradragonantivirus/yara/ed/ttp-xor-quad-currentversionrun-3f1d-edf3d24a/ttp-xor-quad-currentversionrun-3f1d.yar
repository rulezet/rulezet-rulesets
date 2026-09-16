rule TTP_XOR_QUAD_CurrentVersionRun_3f1d {
  strings:
    $key_3f1d = { 6c 72 [2] 48 7c [2] 63 50 [2] 4d 72 [2] 59 69 [2] 56 73 [2] 48 6e [2] 4a 6f [2] 51 69 [2] 4d 6e [2] 51 41 }

  condition:
    any of them
}