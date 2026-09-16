rule TTP_XOR_QUAD_CurrentVersionRun_320c {
  strings:
    $key_320c = { 61 63 [2] 45 6d [2] 6e 41 [2] 40 63 [2] 54 78 [2] 5b 62 [2] 45 7f [2] 47 7e [2] 5c 78 [2] 40 7f [2] 5c 50 }

  condition:
    any of them
}