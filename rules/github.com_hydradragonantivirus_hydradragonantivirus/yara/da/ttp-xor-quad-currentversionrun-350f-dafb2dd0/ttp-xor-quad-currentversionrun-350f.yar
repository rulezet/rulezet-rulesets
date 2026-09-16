rule TTP_XOR_QUAD_CurrentVersionRun_350f {
  strings:
    $key_350f = { 66 60 [2] 42 6e [2] 69 42 [2] 47 60 [2] 53 7b [2] 5c 61 [2] 42 7c [2] 40 7d [2] 5b 7b [2] 47 7c [2] 5b 53 }

  condition:
    any of them
}