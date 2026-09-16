rule TTP_XOR_QUAD_CurrentVersionRun_f2e2 {
  strings:
    $key_f2e2 = { a1 8d [2] 85 83 [2] ae af [2] 80 8d [2] 94 96 [2] 9b 8c [2] 85 91 [2] 87 90 [2] 9c 96 [2] 80 91 [2] 9c be }

  condition:
    any of them
}