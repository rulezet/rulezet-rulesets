rule TTP_XOR_QUAD_CurrentVersionRun_720f {
  strings:
    $key_720f = { 21 60 [2] 05 6e [2] 2e 42 [2] 00 60 [2] 14 7b [2] 1b 61 [2] 05 7c [2] 07 7d [2] 1c 7b [2] 00 7c [2] 1c 53 }

  condition:
    any of them
}