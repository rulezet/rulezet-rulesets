rule TTP_XOR_WriteProcessMemory_cc4c {
  strings:
    $key_cc4c = { 9b 3e [2] a9 1c [2] af 29 [2] 81 29 [2] be 35 }

  condition:
    any of them
}