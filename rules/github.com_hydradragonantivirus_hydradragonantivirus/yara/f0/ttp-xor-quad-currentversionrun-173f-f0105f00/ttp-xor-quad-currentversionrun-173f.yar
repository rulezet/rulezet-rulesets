rule TTP_XOR_QUAD_CurrentVersionRun_173f {
  strings:
    $key_173f = { 44 50 [2] 60 5e [2] 4b 72 [2] 65 50 [2] 71 4b [2] 7e 51 [2] 60 4c [2] 62 4d [2] 79 4b [2] 65 4c [2] 79 63 }

  condition:
    any of them
}