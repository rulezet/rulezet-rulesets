rule TTP_XOR_QUAD_CurrentVersionRun_493a {
  strings:
    $key_493a = { 1a 55 [2] 3e 5b [2] 15 77 [2] 3b 55 [2] 2f 4e [2] 20 54 [2] 3e 49 [2] 3c 48 [2] 27 4e [2] 3b 49 [2] 27 66 }

  condition:
    any of them
}