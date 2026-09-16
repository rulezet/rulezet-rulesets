rule TTP_XOR_QUAD_CurrentVersionRun_270d {
  strings:
    $key_270d = { 74 62 [2] 50 6c [2] 7b 40 [2] 55 62 [2] 41 79 [2] 4e 63 [2] 50 7e [2] 52 7f [2] 49 79 [2] 55 7e [2] 49 51 }

  condition:
    any of them
}