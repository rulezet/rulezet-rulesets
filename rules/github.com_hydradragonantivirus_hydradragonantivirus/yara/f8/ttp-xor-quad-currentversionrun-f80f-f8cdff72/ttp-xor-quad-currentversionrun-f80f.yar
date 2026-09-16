rule TTP_XOR_QUAD_CurrentVersionRun_f80f {
  strings:
    $key_f80f = { ab 60 [2] 8f 6e [2] a4 42 [2] 8a 60 [2] 9e 7b [2] 91 61 [2] 8f 7c [2] 8d 7d [2] 96 7b [2] 8a 7c [2] 96 53 }

  condition:
    any of them
}