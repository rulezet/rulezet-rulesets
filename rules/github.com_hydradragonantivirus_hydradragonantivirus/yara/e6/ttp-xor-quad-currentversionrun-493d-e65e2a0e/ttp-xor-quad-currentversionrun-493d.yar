rule TTP_XOR_QUAD_CurrentVersionRun_493d {
  strings:
    $key_493d = { 1a 52 [2] 3e 5c [2] 15 70 [2] 3b 52 [2] 2f 49 [2] 20 53 [2] 3e 4e [2] 3c 4f [2] 27 49 [2] 3b 4e [2] 27 61 }

  condition:
    any of them
}