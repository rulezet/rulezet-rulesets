rule TTP_XOR_QUAD_CurrentVersionRun_c1fe {
  strings:
    $key_c1fe = { 92 91 [2] b6 9f [2] 9d b3 [2] b3 91 [2] a7 8a [2] a8 90 [2] b6 8d [2] b4 8c [2] af 8a [2] b3 8d [2] af a2 }

  condition:
    any of them
}