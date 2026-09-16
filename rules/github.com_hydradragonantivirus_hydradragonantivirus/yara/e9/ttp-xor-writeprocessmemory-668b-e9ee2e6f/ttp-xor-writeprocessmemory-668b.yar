rule TTP_XOR_WriteProcessMemory_668b {
  strings:
    $key_668b = { 31 f9 [2] 03 db [2] 05 ee [2] 2b ee [2] 14 f2 }

  condition:
    any of them
}