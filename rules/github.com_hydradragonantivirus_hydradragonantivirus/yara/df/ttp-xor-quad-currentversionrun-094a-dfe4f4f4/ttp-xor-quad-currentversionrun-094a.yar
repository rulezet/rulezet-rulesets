rule TTP_XOR_QUAD_CurrentVersionRun_094a {
  strings:
    $key_094a = { 5a 25 [2] 7e 2b [2] 55 07 [2] 7b 25 [2] 6f 3e [2] 60 24 [2] 7e 39 [2] 7c 38 [2] 67 3e [2] 7b 39 [2] 67 16 }

  condition:
    any of them
}