rule TTP_XOR_QUAD_CurrentVersionRun_b9f2 {
  strings:
    $key_b9f2 = { ea 9d [2] ce 93 [2] e5 bf [2] cb 9d [2] df 86 [2] d0 9c [2] ce 81 [2] cc 80 [2] d7 86 [2] cb 81 [2] d7 ae }

  condition:
    any of them
}