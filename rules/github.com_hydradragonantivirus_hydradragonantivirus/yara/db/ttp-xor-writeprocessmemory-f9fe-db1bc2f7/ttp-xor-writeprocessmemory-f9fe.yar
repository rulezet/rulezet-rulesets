rule TTP_XOR_WriteProcessMemory_f9fe {
  strings:
    $key_f9fe = { ae 8c [2] 9c ae [2] 9a 9b [2] b4 9b [2] 8b 87 }

  condition:
    any of them
}