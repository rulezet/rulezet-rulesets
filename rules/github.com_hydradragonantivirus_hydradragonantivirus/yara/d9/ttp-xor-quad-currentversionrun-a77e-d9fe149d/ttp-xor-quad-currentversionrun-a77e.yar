rule TTP_XOR_QUAD_CurrentVersionRun_a77e {
  strings:
    $key_a77e = { f4 11 [2] d0 1f [2] fb 33 [2] d5 11 [2] c1 0a [2] ce 10 [2] d0 0d [2] d2 0c [2] c9 0a [2] d5 0d [2] c9 22 }

  condition:
    any of them
}