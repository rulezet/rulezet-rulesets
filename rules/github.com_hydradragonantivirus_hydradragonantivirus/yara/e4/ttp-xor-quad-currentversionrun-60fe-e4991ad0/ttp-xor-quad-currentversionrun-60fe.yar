rule TTP_XOR_QUAD_CurrentVersionRun_60fe {
  strings:
    $key_60fe = { 33 91 [2] 17 9f [2] 3c b3 [2] 12 91 [2] 06 8a [2] 09 90 [2] 17 8d [2] 15 8c [2] 0e 8a [2] 12 8d [2] 0e a2 }

  condition:
    any of them
}