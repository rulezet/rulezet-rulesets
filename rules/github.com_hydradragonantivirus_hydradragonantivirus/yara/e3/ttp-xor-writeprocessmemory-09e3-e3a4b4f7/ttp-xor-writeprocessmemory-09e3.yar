rule TTP_XOR_WriteProcessMemory_09e3 {
  strings:
    $key_09e3 = { 5e 91 [2] 6c b3 [2] 6a 86 [2] 44 86 [2] 7b 9a }

  condition:
    any of them
}