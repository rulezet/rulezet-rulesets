rule TTP_XOR_WriteProcessMemory_245c {
  strings:
    $key_245c = { 73 2e [2] 41 0c [2] 47 39 [2] 69 39 [2] 56 25 }

  condition:
    any of them
}