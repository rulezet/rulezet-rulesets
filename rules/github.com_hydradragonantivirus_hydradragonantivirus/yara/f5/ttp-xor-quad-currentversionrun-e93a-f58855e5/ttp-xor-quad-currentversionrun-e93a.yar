rule TTP_XOR_QUAD_CurrentVersionRun_e93a {
  strings:
    $key_e93a = { ba 55 [2] 9e 5b [2] b5 77 [2] 9b 55 [2] 8f 4e [2] 80 54 [2] 9e 49 [2] 9c 48 [2] 87 4e [2] 9b 49 [2] 87 66 }

  condition:
    any of them
}