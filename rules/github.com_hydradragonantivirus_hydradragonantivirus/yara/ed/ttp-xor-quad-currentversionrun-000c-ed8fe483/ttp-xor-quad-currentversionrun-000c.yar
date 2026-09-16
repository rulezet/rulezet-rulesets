rule TTP_XOR_QUAD_CurrentVersionRun_000c {
  strings:
    $key_000c = { 53 63 [2] 77 6d [2] 5c 41 [2] 72 63 [2] 66 78 [2] 69 62 [2] 77 7f [2] 75 7e [2] 6e 78 [2] 72 7f [2] 6e 50 }

  condition:
    any of them
}