rule TTP_XOR_QUAD_CurrentVersionRun_060f {
  strings:
    $key_060f = { 55 60 [2] 71 6e [2] 5a 42 [2] 74 60 [2] 60 7b [2] 6f 61 [2] 71 7c [2] 73 7d [2] 68 7b [2] 74 7c [2] 68 53 }

  condition:
    any of them
}