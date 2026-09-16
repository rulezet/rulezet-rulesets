rule TTP_XOR_WriteProcessMemory_f8f9 {
  strings:
    $key_f8f9 = { af 8b [2] 9d a9 [2] 9b 9c [2] b5 9c [2] 8a 80 }

  condition:
    any of them
}