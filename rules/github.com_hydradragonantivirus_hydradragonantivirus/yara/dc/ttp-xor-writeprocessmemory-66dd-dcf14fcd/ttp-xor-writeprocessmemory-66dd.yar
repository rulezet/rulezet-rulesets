rule TTP_XOR_WriteProcessMemory_66dd {
  strings:
    $key_66dd = { 31 af [2] 03 8d [2] 05 b8 [2] 2b b8 [2] 14 a4 }

  condition:
    any of them
}