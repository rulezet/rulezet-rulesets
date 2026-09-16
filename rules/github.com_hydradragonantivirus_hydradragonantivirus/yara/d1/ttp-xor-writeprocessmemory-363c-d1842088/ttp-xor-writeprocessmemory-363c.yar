rule TTP_XOR_WriteProcessMemory_363c {
  strings:
    $key_363c = { 61 4e [2] 53 6c [2] 55 59 [2] 7b 59 [2] 44 45 }

  condition:
    any of them
}