rule TTP_XOR_QUAD_CurrentVersionRun_207d {
  strings:
    $key_207d = { 73 12 [2] 57 1c [2] 7c 30 [2] 52 12 [2] 46 09 [2] 49 13 [2] 57 0e [2] 55 0f [2] 4e 09 [2] 52 0e [2] 4e 21 }

  condition:
    any of them
}