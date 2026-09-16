rule TTP_XOR_QUAD_CurrentVersionRun_6bfe {
  strings:
    $key_6bfe = { 38 91 [2] 1c 9f [2] 37 b3 [2] 19 91 [2] 0d 8a [2] 02 90 [2] 1c 8d [2] 1e 8c [2] 05 8a [2] 19 8d [2] 05 a2 }

  condition:
    any of them
}