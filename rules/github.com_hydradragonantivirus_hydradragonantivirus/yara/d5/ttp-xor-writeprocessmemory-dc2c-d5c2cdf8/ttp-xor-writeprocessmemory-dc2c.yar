rule TTP_XOR_WriteProcessMemory_dc2c {
  strings:
    $key_dc2c = { 8b 5e [2] b9 7c [2] bf 49 [2] 91 49 [2] ae 55 }

  condition:
    any of them
}