rule TTP_XOR_QUAD_CurrentVersionRun_290d {
  strings:
    $key_290d = { 7a 62 [2] 5e 6c [2] 75 40 [2] 5b 62 [2] 4f 79 [2] 40 63 [2] 5e 7e [2] 5c 7f [2] 47 79 [2] 5b 7e [2] 47 51 }

  condition:
    any of them
}