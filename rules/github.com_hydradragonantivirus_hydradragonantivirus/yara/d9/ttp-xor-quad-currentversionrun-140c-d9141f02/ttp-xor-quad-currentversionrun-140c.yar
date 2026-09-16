rule TTP_XOR_QUAD_CurrentVersionRun_140c {
  strings:
    $key_140c = { 47 63 [2] 63 6d [2] 48 41 [2] 66 63 [2] 72 78 [2] 7d 62 [2] 63 7f [2] 61 7e [2] 7a 78 [2] 66 7f [2] 7a 50 }

  condition:
    any of them
}