rule TTP_XOR_QUAD_CurrentVersionRun_32fe {
  strings:
    $key_32fe = { 61 91 [2] 45 9f [2] 6e b3 [2] 40 91 [2] 54 8a [2] 5b 90 [2] 45 8d [2] 47 8c [2] 5c 8a [2] 40 8d [2] 5c a2 }

  condition:
    any of them
}