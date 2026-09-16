rule TTP_XOR_QUAD_CurrentVersionRun_2e0d {
  strings:
    $key_2e0d = { 7d 62 [2] 59 6c [2] 72 40 [2] 5c 62 [2] 48 79 [2] 47 63 [2] 59 7e [2] 5b 7f [2] 40 79 [2] 5c 7e [2] 40 51 }

  condition:
    any of them
}