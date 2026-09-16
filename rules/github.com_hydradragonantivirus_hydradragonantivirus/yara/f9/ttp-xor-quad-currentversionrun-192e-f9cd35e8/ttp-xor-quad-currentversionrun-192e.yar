rule TTP_XOR_QUAD_CurrentVersionRun_192e {
  strings:
    $key_192e = { 4a 41 [2] 6e 4f [2] 45 63 [2] 6b 41 [2] 7f 5a [2] 70 40 [2] 6e 5d [2] 6c 5c [2] 77 5a [2] 6b 5d [2] 77 72 }

  condition:
    any of them
}