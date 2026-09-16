rule TTP_XOR_QUAD_CurrentVersionRun_150f {
  strings:
    $key_150f = { 46 60 [2] 62 6e [2] 49 42 [2] 67 60 [2] 73 7b [2] 7c 61 [2] 62 7c [2] 60 7d [2] 7b 7b [2] 67 7c [2] 7b 53 }

  condition:
    any of them
}