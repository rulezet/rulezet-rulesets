rule TTP_XOR_QUAD_CurrentVersionRun_effe {
  strings:
    $key_effe = { bc 91 [2] 98 9f [2] b3 b3 [2] 9d 91 [2] 89 8a [2] 86 90 [2] 98 8d [2] 9a 8c [2] 81 8a [2] 9d 8d [2] 81 a2 }

  condition:
    any of them
}