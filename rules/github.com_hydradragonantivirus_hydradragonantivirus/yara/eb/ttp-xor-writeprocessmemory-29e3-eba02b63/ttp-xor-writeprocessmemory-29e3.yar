rule TTP_XOR_WriteProcessMemory_29e3 {
  strings:
    $key_29e3 = { 7e 91 [2] 4c b3 [2] 4a 86 [2] 64 86 [2] 5b 9a }

  condition:
    any of them
}