rule TTP_XOR_QUAD_CurrentVersionRun_b93e {
  strings:
    $key_b93e = { ea 51 [2] ce 5f [2] e5 73 [2] cb 51 [2] df 4a [2] d0 50 [2] ce 4d [2] cc 4c [2] d7 4a [2] cb 4d [2] d7 62 }

  condition:
    any of them
}