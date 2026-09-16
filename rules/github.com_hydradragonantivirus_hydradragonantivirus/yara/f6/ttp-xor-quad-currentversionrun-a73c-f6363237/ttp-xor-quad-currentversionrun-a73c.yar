rule TTP_XOR_QUAD_CurrentVersionRun_a73c {
  strings:
    $key_a73c = { f4 53 [2] d0 5d [2] fb 71 [2] d5 53 [2] c1 48 [2] ce 52 [2] d0 4f [2] d2 4e [2] c9 48 [2] d5 4f [2] c9 60 }

  condition:
    any of them
}