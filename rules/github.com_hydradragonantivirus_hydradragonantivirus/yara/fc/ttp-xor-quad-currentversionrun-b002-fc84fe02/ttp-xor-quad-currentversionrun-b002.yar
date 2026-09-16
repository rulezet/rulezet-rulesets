rule TTP_XOR_QUAD_CurrentVersionRun_b002 {
  strings:
    $key_b002 = { e3 6d [2] c7 63 [2] ec 4f [2] c2 6d [2] d6 76 [2] d9 6c [2] c7 71 [2] c5 70 [2] de 76 [2] c2 71 [2] de 5e }

  condition:
    any of them
}