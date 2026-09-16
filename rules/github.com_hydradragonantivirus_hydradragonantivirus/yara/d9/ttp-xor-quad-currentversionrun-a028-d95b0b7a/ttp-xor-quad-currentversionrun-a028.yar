rule TTP_XOR_QUAD_CurrentVersionRun_a028 {
  strings:
    $key_a028 = { f3 47 [2] d7 49 [2] fc 65 [2] d2 47 [2] c6 5c [2] c9 46 [2] d7 5b [2] d5 5a [2] ce 5c [2] d2 5b [2] ce 74 }

  condition:
    any of them
}