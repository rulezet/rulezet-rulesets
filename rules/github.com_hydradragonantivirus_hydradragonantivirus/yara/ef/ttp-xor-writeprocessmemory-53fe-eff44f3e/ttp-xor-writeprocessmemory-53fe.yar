rule TTP_XOR_WriteProcessMemory_53fe {
  strings:
    $key_53fe = { 04 8c [2] 36 ae [2] 30 9b [2] 1e 9b [2] 21 87 }

  condition:
    any of them
}