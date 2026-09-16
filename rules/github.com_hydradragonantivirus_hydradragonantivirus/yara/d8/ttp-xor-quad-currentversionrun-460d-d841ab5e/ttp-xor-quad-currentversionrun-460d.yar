rule TTP_XOR_QUAD_CurrentVersionRun_460d {
  strings:
    $key_460d = { 15 62 [2] 31 6c [2] 1a 40 [2] 34 62 [2] 20 79 [2] 2f 63 [2] 31 7e [2] 33 7f [2] 28 79 [2] 34 7e [2] 28 51 }

  condition:
    any of them
}