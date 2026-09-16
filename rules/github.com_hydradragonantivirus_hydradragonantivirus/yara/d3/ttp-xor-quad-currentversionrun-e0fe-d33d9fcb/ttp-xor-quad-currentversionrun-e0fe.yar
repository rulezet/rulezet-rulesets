rule TTP_XOR_QUAD_CurrentVersionRun_e0fe {
  strings:
    $key_e0fe = { b3 91 [2] 97 9f [2] bc b3 [2] 92 91 [2] 86 8a [2] 89 90 [2] 97 8d [2] 95 8c [2] 8e 8a [2] 92 8d [2] 8e a2 }

  condition:
    any of them
}