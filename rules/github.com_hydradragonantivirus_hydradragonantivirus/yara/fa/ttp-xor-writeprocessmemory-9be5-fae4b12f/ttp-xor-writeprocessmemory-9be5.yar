rule TTP_XOR_WriteProcessMemory_9be5 {
  strings:
    $key_9be5 = { cc 97 [2] fe b5 [2] f8 80 [2] d6 80 [2] e9 9c }

  condition:
    any of them
}