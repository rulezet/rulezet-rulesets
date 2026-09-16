rule TTP_XOR_WriteProcessMemory_0965 {
  strings:
    $key_0965 = { 5e 17 [2] 6c 35 [2] 6a 00 [2] 44 00 [2] 7b 1c }

  condition:
    any of them
}