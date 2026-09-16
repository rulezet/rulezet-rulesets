rule TTP_XOR_WriteProcessMemory_db4b {
  strings:
    $key_db4b = { 8c 39 [2] be 1b [2] b8 2e [2] 96 2e [2] a9 32 }

  condition:
    any of them
}