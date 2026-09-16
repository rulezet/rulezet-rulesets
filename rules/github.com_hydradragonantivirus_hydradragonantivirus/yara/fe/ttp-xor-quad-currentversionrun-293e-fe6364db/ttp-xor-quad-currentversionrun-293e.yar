rule TTP_XOR_QUAD_CurrentVersionRun_293e {
  strings:
    $key_293e = { 7a 51 [2] 5e 5f [2] 75 73 [2] 5b 51 [2] 4f 4a [2] 40 50 [2] 5e 4d [2] 5c 4c [2] 47 4a [2] 5b 4d [2] 47 62 }

  condition:
    any of them
}