rule TTP_XOR_QUAD_CurrentVersionRun_b90f {
  strings:
    $key_b90f = { ea 60 [2] ce 6e [2] e5 42 [2] cb 60 [2] df 7b [2] d0 61 [2] ce 7c [2] cc 7d [2] d7 7b [2] cb 7c [2] d7 53 }

  condition:
    any of them
}