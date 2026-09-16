rule TTP_XOR_QUAD_CurrentVersionRun_e30f {
  strings:
    $key_e30f = { b0 60 [2] 94 6e [2] bf 42 [2] 91 60 [2] 85 7b [2] 8a 61 [2] 94 7c [2] 96 7d [2] 8d 7b [2] 91 7c [2] 8d 53 }

  condition:
    any of them
}