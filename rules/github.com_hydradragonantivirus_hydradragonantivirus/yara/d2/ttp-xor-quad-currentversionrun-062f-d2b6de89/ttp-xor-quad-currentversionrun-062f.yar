rule TTP_XOR_QUAD_CurrentVersionRun_062f {
  strings:
    $key_062f = { 55 40 [2] 71 4e [2] 5a 62 [2] 74 40 [2] 60 5b [2] 6f 41 [2] 71 5c [2] 73 5d [2] 68 5b [2] 74 5c [2] 68 73 }

  condition:
    any of them
}