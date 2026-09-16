rule TTP_XOR_WriteProcessMemory_0c3c {
  strings:
    $key_0c3c = { 5b 4e [2] 69 6c [2] 6f 59 [2] 41 59 [2] 7e 45 }

  condition:
    any of them
}