rule TTP_XOR_WriteProcessMemory_f4b9 {
  strings:
    $key_f4b9 = { a3 cb [2] 91 e9 [2] 97 dc [2] b9 dc [2] 86 c0 }

  condition:
    any of them
}