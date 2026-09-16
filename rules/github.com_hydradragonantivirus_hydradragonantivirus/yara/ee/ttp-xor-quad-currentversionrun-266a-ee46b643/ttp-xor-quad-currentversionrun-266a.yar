rule TTP_XOR_QUAD_CurrentVersionRun_266a {
  strings:
    $key_266a = { 75 05 [2] 51 0b [2] 7a 27 [2] 54 05 [2] 40 1e [2] 4f 04 [2] 51 19 [2] 53 18 [2] 48 1e [2] 54 19 [2] 48 36 }

  condition:
    any of them
}