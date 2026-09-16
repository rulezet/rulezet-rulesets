rule TTP_XOR_WriteProcessMemory_e62c {
  strings:
    $key_e62c = { b1 5e [2] 83 7c [2] 85 49 [2] ab 49 [2] 94 55 }

  condition:
    any of them
}