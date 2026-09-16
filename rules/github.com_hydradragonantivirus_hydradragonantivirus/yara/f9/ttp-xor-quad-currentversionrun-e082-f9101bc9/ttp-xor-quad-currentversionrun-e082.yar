rule TTP_XOR_QUAD_CurrentVersionRun_e082 {
  strings:
    $key_e082 = { b3 ed [2] 97 e3 [2] bc cf [2] 92 ed [2] 86 f6 [2] 89 ec [2] 97 f1 [2] 95 f0 [2] 8e f6 [2] 92 f1 [2] 8e de }

  condition:
    any of them
}