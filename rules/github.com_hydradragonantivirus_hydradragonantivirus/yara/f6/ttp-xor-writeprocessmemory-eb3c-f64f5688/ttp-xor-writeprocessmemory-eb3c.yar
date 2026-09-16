rule TTP_XOR_WriteProcessMemory_eb3c {
  strings:
    $key_eb3c = { bc 4e [2] 8e 6c [2] 88 59 [2] a6 59 [2] 99 45 }

  condition:
    any of them
}