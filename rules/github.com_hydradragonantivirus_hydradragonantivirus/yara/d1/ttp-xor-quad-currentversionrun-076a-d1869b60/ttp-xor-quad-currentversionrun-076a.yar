rule TTP_XOR_QUAD_CurrentVersionRun_076a {
  strings:
    $key_076a = { 54 05 [2] 70 0b [2] 5b 27 [2] 75 05 [2] 61 1e [2] 6e 04 [2] 70 19 [2] 72 18 [2] 69 1e [2] 75 19 [2] 69 36 }

  condition:
    any of them
}