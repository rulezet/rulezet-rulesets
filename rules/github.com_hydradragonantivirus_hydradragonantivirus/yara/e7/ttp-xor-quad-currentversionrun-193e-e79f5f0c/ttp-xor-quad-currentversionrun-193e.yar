rule TTP_XOR_QUAD_CurrentVersionRun_193e {
  strings:
    $key_193e = { 4a 51 [2] 6e 5f [2] 45 73 [2] 6b 51 [2] 7f 4a [2] 70 50 [2] 6e 4d [2] 6c 4c [2] 77 4a [2] 6b 4d [2] 77 62 }

  condition:
    any of them
}