rule TTP_XOR_QUAD_CurrentVersionRun_05e3 {
  strings:
    $key_05e3 = { 56 8c [2] 72 82 [2] 59 ae [2] 77 8c [2] 63 97 [2] 6c 8d [2] 72 90 [2] 70 91 [2] 6b 97 [2] 77 90 [2] 6b bf }

  condition:
    any of them
}