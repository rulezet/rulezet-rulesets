rule TTP_XOR_QUAD_CurrentVersionRun_670c {
  strings:
    $key_670c = { 34 63 [2] 10 6d [2] 3b 41 [2] 15 63 [2] 01 78 [2] 0e 62 [2] 10 7f [2] 12 7e [2] 09 78 [2] 15 7f [2] 09 50 }

  condition:
    any of them
}