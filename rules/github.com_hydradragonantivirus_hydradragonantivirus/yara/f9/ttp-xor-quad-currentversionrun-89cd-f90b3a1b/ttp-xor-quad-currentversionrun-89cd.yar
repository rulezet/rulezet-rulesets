rule TTP_XOR_QUAD_CurrentVersionRun_89cd {
  strings:
    $key_89cd = { da a2 [2] fe ac [2] d5 80 [2] fb a2 [2] ef b9 [2] e0 a3 [2] fe be [2] fc bf [2] e7 b9 [2] fb be [2] e7 91 }

  condition:
    any of them
}