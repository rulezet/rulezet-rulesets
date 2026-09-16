rule TTP_XOR_QUAD_CurrentVersionRun_b92f {
  strings:
    $key_b92f = { ea 40 [2] ce 4e [2] e5 62 [2] cb 40 [2] df 5b [2] d0 41 [2] ce 5c [2] cc 5d [2] d7 5b [2] cb 5c [2] d7 73 }

  condition:
    any of them
}