rule TTP_XOR_QUAD_CurrentVersionRun_097e {
  strings:
    $key_097e = { 5a 11 [2] 7e 1f [2] 55 33 [2] 7b 11 [2] 6f 0a [2] 60 10 [2] 7e 0d [2] 7c 0c [2] 67 0a [2] 7b 0d [2] 67 22 }

  condition:
    any of them
}