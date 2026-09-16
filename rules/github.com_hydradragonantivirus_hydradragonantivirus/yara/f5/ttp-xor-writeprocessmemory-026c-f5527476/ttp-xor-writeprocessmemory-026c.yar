rule TTP_XOR_WriteProcessMemory_026c {
  strings:
    $key_026c = { 55 1e [2] 67 3c [2] 61 09 [2] 4f 09 [2] 70 15 }

  condition:
    any of them
}