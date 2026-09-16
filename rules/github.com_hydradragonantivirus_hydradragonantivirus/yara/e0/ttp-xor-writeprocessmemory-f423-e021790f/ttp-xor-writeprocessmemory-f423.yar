rule TTP_XOR_WriteProcessMemory_f423 {
  strings:
    $key_f423 = { a3 51 [2] 91 73 [2] 97 46 [2] b9 46 [2] 86 5a }

  condition:
    any of them
}