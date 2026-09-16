rule TTP_XOR_QUAD_CurrentVersionRun_a4e3 {
  strings:
    $key_a4e3 = { f7 8c [2] d3 82 [2] f8 ae [2] d6 8c [2] c2 97 [2] cd 8d [2] d3 90 [2] d1 91 [2] ca 97 [2] d6 90 [2] ca bf }

  condition:
    any of them
}