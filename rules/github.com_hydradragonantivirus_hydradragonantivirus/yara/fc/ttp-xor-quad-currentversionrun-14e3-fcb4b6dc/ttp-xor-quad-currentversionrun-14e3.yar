rule TTP_XOR_QUAD_CurrentVersionRun_14e3 {
  strings:
    $key_14e3 = { 47 8c [2] 63 82 [2] 48 ae [2] 66 8c [2] 72 97 [2] 7d 8d [2] 63 90 [2] 61 91 [2] 7a 97 [2] 66 90 [2] 7a bf }

  condition:
    any of them
}