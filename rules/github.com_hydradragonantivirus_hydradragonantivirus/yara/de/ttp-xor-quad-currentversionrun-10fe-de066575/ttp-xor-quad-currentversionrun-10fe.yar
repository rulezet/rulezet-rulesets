rule TTP_XOR_QUAD_CurrentVersionRun_10fe {
  strings:
    $key_10fe = { 43 91 [2] 67 9f [2] 4c b3 [2] 62 91 [2] 76 8a [2] 79 90 [2] 67 8d [2] 65 8c [2] 7e 8a [2] 62 8d [2] 7e a2 }

  condition:
    any of them
}