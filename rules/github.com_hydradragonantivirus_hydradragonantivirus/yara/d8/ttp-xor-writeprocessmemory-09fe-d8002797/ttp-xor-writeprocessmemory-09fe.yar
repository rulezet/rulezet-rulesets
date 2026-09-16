rule TTP_XOR_WriteProcessMemory_09fe {
  strings:
    $key_09fe = { 5e 8c [2] 6c ae [2] 6a 9b [2] 44 9b [2] 7b 87 }

  condition:
    any of them
}