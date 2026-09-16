rule TTP_XOR_WriteProcessMemory_085c {
  strings:
    $key_085c = { 5f 2e [2] 6d 0c [2] 6b 39 [2] 45 39 [2] 7a 25 }

  condition:
    any of them
}