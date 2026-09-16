rule TTP_XOR_WriteProcessMemory_19e3 {
  strings:
    $key_19e3 = { 4e 91 [2] 7c b3 [2] 7a 86 [2] 54 86 [2] 6b 9a }

  condition:
    any of them
}