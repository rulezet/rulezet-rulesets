rule TTP_XOR_WriteProcessMemory_19e8 {
  strings:
    $key_19e8 = { 4e 9a [2] 7c b8 [2] 7a 8d [2] 54 8d [2] 6b 91 }

  condition:
    any of them
}