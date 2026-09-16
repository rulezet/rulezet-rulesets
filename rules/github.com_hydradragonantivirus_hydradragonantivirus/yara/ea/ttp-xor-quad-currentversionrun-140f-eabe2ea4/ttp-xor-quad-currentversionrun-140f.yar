rule TTP_XOR_QUAD_CurrentVersionRun_140f {
  strings:
    $key_140f = { 47 60 [2] 63 6e [2] 48 42 [2] 66 60 [2] 72 7b [2] 7d 61 [2] 63 7c [2] 61 7d [2] 7a 7b [2] 66 7c [2] 7a 53 }

  condition:
    any of them
}