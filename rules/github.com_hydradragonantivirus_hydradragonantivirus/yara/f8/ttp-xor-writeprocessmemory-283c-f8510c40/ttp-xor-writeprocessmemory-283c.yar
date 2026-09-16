rule TTP_XOR_WriteProcessMemory_283c {
  strings:
    $key_283c = { 7f 4e [2] 4d 6c [2] 4b 59 [2] 65 59 [2] 5a 45 }

  condition:
    any of them
}