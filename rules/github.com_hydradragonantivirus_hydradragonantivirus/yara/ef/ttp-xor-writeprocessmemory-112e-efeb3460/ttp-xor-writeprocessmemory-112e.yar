rule TTP_XOR_WriteProcessMemory_112e {
  strings:
    $key_112e = { 46 5c [2] 74 7e [2] 72 4b [2] 5c 4b [2] 63 57 }

  condition:
    any of them
}