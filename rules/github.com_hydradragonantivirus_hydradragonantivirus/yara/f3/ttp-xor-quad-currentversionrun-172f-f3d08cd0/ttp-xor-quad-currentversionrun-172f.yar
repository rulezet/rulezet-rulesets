rule TTP_XOR_QUAD_CurrentVersionRun_172f {
  strings:
    $key_172f = { 44 40 [2] 60 4e [2] 4b 62 [2] 65 40 [2] 71 5b [2] 7e 41 [2] 60 5c [2] 62 5d [2] 79 5b [2] 65 5c [2] 79 73 }

  condition:
    any of them
}