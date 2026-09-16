rule TTP_XOR_WriteProcessMemory_238b {
  strings:
    $key_238b = { 74 f9 [2] 46 db [2] 40 ee [2] 6e ee [2] 51 f2 }

  condition:
    any of them
}