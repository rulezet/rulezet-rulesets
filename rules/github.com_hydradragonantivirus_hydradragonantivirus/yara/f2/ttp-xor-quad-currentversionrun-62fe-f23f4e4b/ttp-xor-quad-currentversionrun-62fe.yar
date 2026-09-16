rule TTP_XOR_QUAD_CurrentVersionRun_62fe {
  strings:
    $key_62fe = { 31 91 [2] 15 9f [2] 3e b3 [2] 10 91 [2] 04 8a [2] 0b 90 [2] 15 8d [2] 17 8c [2] 0c 8a [2] 10 8d [2] 0c a2 }

  condition:
    any of them
}