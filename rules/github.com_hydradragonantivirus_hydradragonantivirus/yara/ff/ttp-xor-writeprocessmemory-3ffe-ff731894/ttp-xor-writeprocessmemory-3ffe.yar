rule TTP_XOR_WriteProcessMemory_3ffe {
  strings:
    $key_3ffe = { 68 8c [2] 5a ae [2] 5c 9b [2] 72 9b [2] 4d 87 }

  condition:
    any of them
}