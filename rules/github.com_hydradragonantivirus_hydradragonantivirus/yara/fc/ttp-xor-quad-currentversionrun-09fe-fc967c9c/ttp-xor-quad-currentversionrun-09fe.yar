rule TTP_XOR_QUAD_CurrentVersionRun_09fe {
  strings:
    $key_09fe = { 5a 91 [2] 7e 9f [2] 55 b3 [2] 7b 91 [2] 6f 8a [2] 60 90 [2] 7e 8d [2] 7c 8c [2] 67 8a [2] 7b 8d [2] 67 a2 }

  condition:
    any of them
}