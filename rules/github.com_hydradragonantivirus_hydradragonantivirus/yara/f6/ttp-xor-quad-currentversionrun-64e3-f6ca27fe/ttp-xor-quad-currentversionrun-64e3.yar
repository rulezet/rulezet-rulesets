rule TTP_XOR_QUAD_CurrentVersionRun_64e3 {
  strings:
    $key_64e3 = { 37 8c [2] 13 82 [2] 38 ae [2] 16 8c [2] 02 97 [2] 0d 8d [2] 13 90 [2] 11 91 [2] 0a 97 [2] 16 90 [2] 0a bf }

  condition:
    any of them
}