rule TTP_XOR_QUAD_CurrentVersionRun_f80c {
  strings:
    $key_f80c = { ab 63 [2] 8f 6d [2] a4 41 [2] 8a 63 [2] 9e 78 [2] 91 62 [2] 8f 7f [2] 8d 7e [2] 96 78 [2] 8a 7f [2] 96 50 }

  condition:
    any of them
}