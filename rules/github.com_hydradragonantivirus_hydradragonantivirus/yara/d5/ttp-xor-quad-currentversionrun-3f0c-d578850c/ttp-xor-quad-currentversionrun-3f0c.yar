rule TTP_XOR_QUAD_CurrentVersionRun_3f0c {
  strings:
    $key_3f0c = { 6c 63 [2] 48 6d [2] 63 41 [2] 4d 63 [2] 59 78 [2] 56 62 [2] 48 7f [2] 4a 7e [2] 51 78 [2] 4d 7f [2] 51 50 }

  condition:
    any of them
}