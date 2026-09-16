rule TTP_XOR_QUAD_CurrentVersionRun_05e2 {
  strings:
    $key_05e2 = { 56 8d [2] 72 83 [2] 59 af [2] 77 8d [2] 63 96 [2] 6c 8c [2] 72 91 [2] 70 90 [2] 6b 96 [2] 77 91 [2] 6b be }

  condition:
    any of them
}