rule TTP_XOR_WriteProcessMemory_748b {
  strings:
    $key_748b = { 23 f9 [2] 11 db [2] 17 ee [2] 39 ee [2] 06 f2 }

  condition:
    any of them
}