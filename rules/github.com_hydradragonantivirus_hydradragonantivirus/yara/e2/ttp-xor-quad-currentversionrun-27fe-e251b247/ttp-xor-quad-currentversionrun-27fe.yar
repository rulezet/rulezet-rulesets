rule TTP_XOR_QUAD_CurrentVersionRun_27fe {
  strings:
    $key_27fe = { 74 91 [2] 50 9f [2] 7b b3 [2] 55 91 [2] 41 8a [2] 4e 90 [2] 50 8d [2] 52 8c [2] 49 8a [2] 55 8d [2] 49 a2 }

  condition:
    any of them
}