rule TTP_XOR_QUAD_CurrentVersionRun_86fe {
  strings:
    $key_86fe = { d5 91 [2] f1 9f [2] da b3 [2] f4 91 [2] e0 8a [2] ef 90 [2] f1 8d [2] f3 8c [2] e8 8a [2] f4 8d [2] e8 a2 }

  condition:
    any of them
}