rule TTP_XOR_QUAD_CurrentVersionRun_726a {
  strings:
    $key_726a = { 21 05 [2] 05 0b [2] 2e 27 [2] 00 05 [2] 14 1e [2] 1b 04 [2] 05 19 [2] 07 18 [2] 1c 1e [2] 00 19 [2] 1c 36 }

  condition:
    any of them
}